#!/usr/bin/env bash
# Assert a published image's `mvm-meta.json` describes a boot contract the
# admission gate will accept.
#
# The sidecar is metadata, so every checksum and signature over it verifies
# happily while it says something the runtime then refuses. `boot-image/v0.1.0`
# failed on every tag push for a day because the sidecar claimed
# `overlayAware: true` without `runtimeLean: true` — a rootfs that requires the
# runtime overlay while also claiming a baked agent fallback. The required-
# overlay gate refuses exactly that pair.
#
# It matters that this is a *static* check. The only thing that caught the
# defect before was the boot gate, which runs on x86_64 alone: GitHub's arm64
# runners have no nested KVM and cannot start a guest. So an aarch64 sidecar
# defect of this class shipped unverified. Reading the JSON needs no KVM, so
# both legs get the same check.
#
# Usage: assert-sidecar-coherent.sh SIDECAR_JSON [LABEL]
set -euo pipefail

sidecar="${1:-}"
label="${2:-$sidecar}"
if [ -z "$sidecar" ]; then
  echo "usage: assert-sidecar-coherent.sh SIDECAR_JSON [LABEL]" >&2
  exit 2
fi
if [ ! -f "$sidecar" ]; then
  echo "assert-sidecar-coherent: $label: no sidecar at $sidecar" >&2
  exit 1
fi

field() {
  # Absent reads as `false`, which is exactly how the runtime treats a missing
  # field — so a dropped key is caught here rather than inverting silently.
  python3 -c '
import json,sys
with open(sys.argv[1]) as f:
    meta = json.load(f)
print("true" if meta.get(sys.argv[2]) is True else "false")
' "$sidecar" "$1"
}

overlay_aware="$(field overlayAware)"
runtime_lean="$(field runtimeLean)"

if [ "$overlay_aware" != "$runtime_lean" ]; then
  echo "assert-sidecar-coherent: $label: overlayAware=$overlay_aware but runtimeLean=$runtime_lean" >&2
  echo "  These describe one decision — whether the rootfs omits the baked agent" >&2
  echo "  fallback — so they must agree. A required-overlay boot refuses this pair," >&2
  echo "  and a checksum over the sidecar cannot see it." >&2
  echo "  Usually a field missing from default-tenant's sidecarJson inherit list." >&2
  exit 1
fi

echo "assert-sidecar-coherent: $label: overlayAware=$overlay_aware runtimeLean=$runtime_lean (coherent)"
