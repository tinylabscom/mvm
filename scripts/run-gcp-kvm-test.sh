#!/usr/bin/env bash
# Run one repository test command on a disposable Google Cloud Spot VM with
# nested KVM. Only git-tracked files from the current checkout are uploaded,
# results are
# downloaded, and the VM is deleted on every exit unless explicitly retained.
set -euo pipefail
# Never hold a billable instance open waiting for an interactive auth prompt.
export CLOUDSDK_CORE_DISABLE_PROMPTS=1

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
    '  --run-as-root           Keep root for explicitly root-owned lab setup' \
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
run_mode=unprivileged
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
    --run-as-root)
      run_mode=root
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
  # Terminal scratch directories can disappear when an agent turn ends.
  # Keep downloaded failure evidence in the machine's durable /tmp instead.
  results_dir="/tmp/mvm-gcp-kvm-results/$run_id"
fi
mkdir -p "$results_dir"

create_args=(
  compute instances create "$instance"
  --project="$project"
  --zone="$zone"
  --machine-type="$machine_type"
  --provisioning-model=SPOT
  --instance-termination-action=DELETE
  --max-run-duration=2h
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
echo "  execution:     $run_mode"
printf '  command:'
printf ' %q' "${remote_command[@]}"
printf '\n'

if ((dry_run)); then
  printf '  create command:'
  printf ' %q' gcloud "${create_args[@]}"
  printf '\n'
  exit 0
fi

if ! gcloud auth print-access-token >/dev/null; then
  echo "error: refresh gcloud authentication before creating a billable test instance" >&2
  exit 1
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
# The API may create the instance before gcloud returns an error (for example,
# a client-side updater crash). Treat even an uncertain create as ours to
# delete; otherwise the EXIT trap could leave a billable VM behind.
instance_created=1
gcloud "${create_args[@]}"

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
git -C "$repo_root" rev-parse --verify 'HEAD^{commit}' >"$local_stage/mvm-source.sha"

gcloud compute scp \
  "$local_stage/mvm-source.tar.gz" "$local_stage/mvm-command.argv" \
  "$local_stage/mvm-source.sha" \
  "$instance:/tmp/" --project="$project" --zone="$zone" --quiet

echo ">> starting the requested test on the host"
# The test can spend half an hour preparing guest artifacts without writing
# output. A single SSH stream is not its owner: local connectivity can drop
# while the remote job is still making progress. systemd owns the job until
# its EXIT trap publishes the result bundle, and short SSH reads reconcile it.
gcloud compute ssh "$instance" --project="$project" --zone="$zone" --quiet \
  --ssh-flag=-oConnectTimeout=15 \
  --command="sudo rm -rf /opt/mvm && sudo mkdir -p /opt/mvm && sudo tar -xzf /tmp/mvm-source.tar.gz -C /opt/mvm --strip-components=1 && sudo systemd-run --unit=mvm-gcp-kvm-test --collect /bin/bash /opt/mvm/scripts/run-gcp-kvm-test-remote.sh /tmp/mvm-command.argv /tmp/mvm-source.sha $run_mode"

deadline=$((SECONDS + 5400))
checks=0
run_status=
echo ">> waiting for the remote result (at most 90 minutes)"
while ((SECONDS < deadline)); do
  # A nonzero test status is file CONTENT, not this SSH command's exit status.
  # Both the exit-status file and archive must exist: the remote EXIT trap
  # writes the former before closing the latter.
  if observed="$(gcloud compute ssh "$instance" --project="$project" --zone="$zone" \
    --quiet --ssh-flag=-oConnectTimeout=15 \
    --command="sudo sh -c 'test -f /var/tmp/mvm-gcp-kvm-results.tar.gz && cat /var/tmp/mvm-gcp-kvm-results/exit-status'" \
    2>/dev/null)" && [[ "$observed" =~ ^[0-9]+$ ]]; then
    run_status="$observed"
    break
  fi
  checks=$((checks + 1))
  if ((checks % 6 == 0)); then
    echo ">> remote result still pending; keeping the test host under its deletion trap"
  fi
  sleep 20
done
if [[ -z "$run_status" ]]; then
  echo "error: the remote test did not publish a result within 90 minutes" >&2
  exit 1
fi

echo ">> downloading the result bundle"
copy_status=1
for delay in 0 1 3 5; do
  if ((delay)); then
    sleep "$delay"
  fi
  if gcloud compute scp "$instance:/var/tmp/mvm-gcp-kvm-results.tar.gz" \
    "$results_dir/" --project="$project" --zone="$zone" --quiet; then
    copy_status=0
    break
  fi
done
if ((copy_status != 0)); then
  echo "error: remote run status $run_status and result download failed" >&2
  exit 1
fi

echo "results: $results_dir/mvm-gcp-kvm-results.tar.gz"
if tar -tzf "$results_dir/mvm-gcp-kvm-results.tar.gz" >/dev/null 2>&1; then
  if tar -tzf "$results_dir/mvm-gcp-kvm-results.tar.gz" \
    mvm-gcp-kvm-results/command.log >/dev/null 2>&1; then
    tar -xOzf "$results_dir/mvm-gcp-kvm-results.tar.gz" \
      mvm-gcp-kvm-results/command.log || true
  else
    tar -xOzf "$results_dir/mvm-gcp-kvm-results.tar.gz" \
      mvm-gcp-kvm-results/bootstrap.log || true
  fi
fi
if ((run_status != 0)); then
  echo "remote test did not pass; inspect the downloaded result bundle" >&2
fi
exit "$run_status"
