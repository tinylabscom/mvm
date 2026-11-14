#!/usr/bin/env bash
# Run only inside the authorized, disposable Linux/KVM test host.
# Arguments carry the tiny, independently built Yocto output through the
# tracked-source-only lab runner; they contain no credentials.
set -euo pipefail

archive_b64=${1:?Yocto rootfs archive (base64) required}
manifest_b64=${2:?Yocto installed-package manifest (base64) required}
expected_sha256=${3:?Yocto archive SHA-256 required}
results=${MVM_GCP_KVM_RESULTS_DIR:?lab runner result directory required}
[[ "$(uname -m)" == x86_64 && -r /dev/kvm && -w /dev/kvm ]] || {
  echo "x86_64 Linux with writable KVM is required" >&2
  exit 1
}
[[ "$expected_sha256" =~ ^[0-9a-f]{64}$ ]] || {
  echo "invalid Yocto archive digest" >&2
  exit 1
}

input=$(mktemp -d /var/tmp/mvm-yocto-pack.XXXXXXXX)
archive="$input/mvm-workload-qemux86-64.rootfs.tar.gz"
manifest="$input/mvm-workload-qemux86-64.rootfs.manifest"
printf '%s' "$archive_b64" | base64 -d >"$archive"
printf '%s' "$manifest_b64" | base64 -d >"$manifest"
printf '%s  %s\n' "$expected_sha256" "$archive" | sha256sum --check
python3 examples/yocto/check_output.py --machine qemux86-64 \
  "$manifest" "$archive" | tee "$results/yocto-output-check.txt"
cp "$manifest" "$results/yocto-package-manifest.txt"
cp "$archive" "$results/yocto-rootfs.tar.gz"
cp examples/yocto/pack-x86_64.json "$input/pack.json"
cp "$input/pack.json" "$results/pack.json"
python3 examples/yocto/write_inputs.py --machine qemux86-64 \
  "$archive" examples/yocto/meta-mvm "$input/yocto-inputs.json"
cp "$input/yocto-inputs.json" "$results/yocto-inputs.json"
git rev-parse HEAD >"$results/source-commit.txt"
git diff --binary HEAD >"$results/source-worktree.patch"
sha256sum "$results/source-worktree.patch" >"$results/source-worktree-patch.sha256"
# The runner restores HEAD with a mixed reset, so newly staged files become
# untracked there. Hash both tracked and transferred new files; HEAD alone
# does not identify the compiled source. Record paths removed from HEAD too.
git ls-files --cached --others --exclude-standard -z | sort -z |
  while IFS= read -r -d '' file; do
    if [[ -L "$file" ]]; then
      echo "linked source member: $file" >&2
      exit 1
    elif [[ -f "$file" ]]; then
      sha256sum -- "$file"
    elif [[ ! -e "$file" ]]; then
      printf 'deleted  %s\n' "$file"
    else
      echo "unsupported source member: $file" >&2
      exit 1
    fi
  done >"$results/source-tree-files.sha256"
sha256sum "$archive" >"$results/yocto-archive.sha256"

cargo build --bin mvmctl --features user,embed-host-bins
cargo build -p mvm-hostd --bin mvm-host-agent --bin mvm-signer-helper --bin mvm-network-endpoint
cargo test -p mvm-client --lib entrypoint_admission_checks_the_selected_backend_not_its_label
cli="${CARGO_TARGET_DIR:-target}/debug/mvmctl"
sha256sum "$cli" >"$results/mvmctl.sha256"
"$cli" --version | tee "$results/mvmctl-version.txt"

# The lab runner prepares tools as root, but Firecracker correctly refuses
# root-owned workload launches. Give one isolated principal the KVM device and
# its own signing state; never relax /dev/kvm permissions.
useradd --create-home --user-group --groups kvm mvm-witness
export MVM_HOME=/home/mvm-witness/.mvm
install -d -o mvm-witness -g mvm-witness -m 0700 "$MVM_HOME"
chown -R mvm-witness:mvm-witness "$input"
chown mvm-witness:mvm-witness "$results"
runuser -u mvm-witness -- test -r /dev/kvm
runuser -u mvm-witness -- test -w /dev/kvm
runuser -u mvm-witness -- id >"$results/launch-principal.txt"

# The Firecracker tier requires a real delegated systemd user scope. An
# SSH/sudo/runuser command alone has no user bus; start the user manager and
# prove it can create a bounded scope before trying any MVM boot.
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends dbus-user-session
loginctl enable-linger mvm-witness
uid=$(id -u mvm-witness)
systemctl start "user@${uid}.service"
runtime_dir="/run/user/$uid"
bus="unix:path=$runtime_dir/bus"
test -S "$runtime_dir/bus"
systemctl show "user@${uid}.service" -p ActiveState -p Delegate \
  >"$results/user-manager.txt"
runuser -u mvm-witness -- env HOME=/home/mvm-witness \
  XDG_RUNTIME_DIR="$runtime_dir" DBUS_SESSION_BUS_ADDRESS="$bus" \
  systemd-run --user --scope --quiet \
    -p MemoryMax=64M -p MemorySwapMax=0 -p TasksMax=128 -p OOMPolicy=stop \
    -- /usr/bin/true
echo "bounded user scope created" >>"$results/user-manager.txt"
cli_as_witness() {
  runuser -u mvm-witness -- env HOME=/home/mvm-witness MVM_HOME="$MVM_HOME" \
    XDG_RUNTIME_DIR="$runtime_dir" DBUS_SESSION_BUS_ADDRESS="$bus" \
    PATH="$PATH" "$cli" "$@"
}

# Portable boot proof requires current, publisher-signed image-set
# revocations. The update verifies both signature and freshness before any
# image-set or guest-runtime acquisition; never synthesize an empty list.
revocations_url=https://github.com/tinylabscom/mvm-images/releases/download/revocations
for name in revocations.json revocations.json.bundle; do
  curl --fail --silent --show-error --location --retry 3 \
    --output "$input/$name" "$revocations_url/$name"
done
cli_as_witness image revocations update \
  --document "$input/revocations.json" --bundle "$input/revocations.json.bundle" \
  | tee "$results/revocation-update.txt"
cli_as_witness image revocations status --json >"$results/revocation-status.json"
cp "$input/revocations.json" "$input/revocations.json.bundle" "$results/"

pack="$results/mvm-yocto-hello.mvmpkg"
cli_as_witness build "$input/pack.json" --hypervisor firecracker --out "$pack" \
  2>&1 | tee "$results/build-health-and-sign.log"
sha256sum "$pack" >"$results/signed-pack.sha256"
cp "$MVM_HOME/keys/host-signer.pub" "$results/host-signer.pub"
cli_as_witness machine check-artifact "$pack" --backend firecracker --json \
  >"$results/check-artifact.json"
python3 - "$results/check-artifact.json" "$expected_sha256" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as evidence:
    verdict = json.load(evidence)
assert verdict["origin"] == "local-build", verdict
assert verdict["arch"] == "x86_64", verdict
assert verdict["host_arch_compatible"] is True, verdict
assert verdict["backend"] == "firecracker", verdict
assert verdict["embedded_image_sets"] == [], verdict
assert verdict["backend_compatibility_checked"] is False, verdict
assert verdict["built_from"] == f"yocto:qemux86-64@sha256:{sys.argv[2]}", verdict
assert verdict["posture"] == {
    "egress": "deny-all",
    "profile": "sealed-prod",
    "requires_auth": True,
    "verity_protected": True,
    "volumes": False,
}, verdict
print("verified local-build signature and artifact digests; backend preview not applicable")
PY

# This is a second, admitted VM boot of the signed archive, not the producer's
# pre-signing health boot. The baked entrypoint must exit 0 and emit its marker.
cli_as_witness machine run --manifest "$pack" --hypervisor firecracker \
  --cpus 1 --memory 256M --entrypoint --fresh \
  2>&1 | tee "$results/signed-pack-run.log"
grep -Fq 'mvm-yocto-health-ok' "$results/signed-pack-run.log"
cli_as_witness trust audit verify >"$results/audit-verify.txt"
cp -a "$MVM_HOME/audit" "$results/audit-chain"
echo "SIGNED_YOCTO_PACK_BOOT_WITNESSED"
