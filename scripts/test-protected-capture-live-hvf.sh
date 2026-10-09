#!/usr/bin/env bash
set -euo pipefail

# This lane consumes already verified fixtures; it does not acquire them, boot
# a preparation VM, sign binaries, run Cucumber, or claim warm/recovery coverage.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "$(uname -s)" != Darwin || "$(uname -m)" != arm64 ]]; then
    echo "requires native Apple Silicon macOS" >&2
    exit 64
fi
: "${MVM_E2E_FIXTURE_HOME:?supply the isolated, verified fixture MVM_HOME}"
: "${MVM_E2E_KERNEL:?supply the verified kernel inside fixture-home/cache}"
: "${MVM_E2E_ROOTFS:?supply the bootable rootfs inside fixture-home/cache}"
: "${MVM_E2E_MVMCTL:?supply the exact integration CLI executable}"
: "${MVM_HVF_SUPERVISOR_PATH:?supply the entitled integration supervisor executable}"
: "${MVM_PROTECTED_WITNESS_TEST_BIN:?supply the compiled protected_capture_live_hvf test executable}"
case "$MVM_E2E_FIXTURE_HOME" in
    /tmp/*|/private/tmp/*) ;;
    *) echo "fixture home must be an explicitly prepared isolated /tmp directory" >&2; exit 65 ;;
esac
for binary in "$MVM_E2E_MVMCTL" "$MVM_HVF_SUPERVISOR_PATH" "$MVM_PROTECTED_WITNESS_TEST_BIN"; do
    [[ "$binary" = /* && -x "$binary" ]] || { echo "missing absolute executable: $binary" >&2; exit 65; }
done
for fixture in "$MVM_E2E_KERNEL" "$MVM_E2E_ROOTFS"; do
    [[ -f "$fixture" && "$fixture" = "$MVM_E2E_FIXTURE_HOME/cache/"* ]] || {
        echo "fixture must be a regular file inside the explicit isolated fixture cache" >&2; exit 65;
    }
done
tests="$("$MVM_PROTECTED_WITNESS_TEST_BIN" --list --ignored)"
grep -qx 'detached_console_survives_launcher_and_seals_on_stop: test' <<< "$tests" || {
    echo "test executable does not contain the native witness; refusing a zero-test pass" >&2; exit 65;
}
entitlements="$(codesign -d --entitlements - --xml "$MVM_HVF_SUPERVISOR_PATH" 2>&1)"
[[ "$entitlements" == *com.apple.security.hypervisor* ]] || {
    echo "supervisor lacks Hypervisor.framework entitlement; fixture owner must sign it" >&2; exit 65;
}

# Source before overriding: dev-env otherwise reclaims external paths.
# shellcheck source=/dev/null
source "$ROOT/scripts/dev-env.sh"
umask 077
export MVM_PROTECTED_WITNESS_ROOT
MVM_PROTECTED_WITNESS_ROOT="$(mktemp -d /tmp/pc-hvf.XXXXXX)"
export MVM_HOME="$MVM_PROTECTED_WITNESS_ROOT/mvm"
export MVM_E2E_HOME="$MVM_HOME"
export HOME="$MVM_PROTECTED_WITNESS_ROOT/home"
export TMPDIR="$MVM_PROTECTED_WITNESS_ROOT/tmp"
mkdir -p "$MVM_HOME" "$HOME" "$TMPDIR"
printf 'cold-detached-v1\n' > "$MVM_PROTECTED_WITNESS_ROOT/protected-witness-owned"
# APFS copy-on-write clones avoid a shared writable cache. No default-home
# import is possible: HOME itself is empty and isolated for the test process.
cp -cR "$MVM_E2E_FIXTURE_HOME/cache" "$MVM_HOME/cache"
export MVM_E2E_KERNEL="$MVM_HOME/cache/${MVM_E2E_KERNEL#"$MVM_E2E_FIXTURE_HOME/cache/"}"
export MVM_E2E_ROOTFS="$MVM_HOME/cache/${MVM_E2E_ROOTFS#"$MVM_E2E_FIXTURE_HOME/cache/"}"
export MVM_KERNEL_SOURCE=download MVM_RESIDENCY=cold
export MVM_RUNTIME_OVERLAY_ACQUIRE_MODE=download
export MVM_LIBKRUN_SUPERVISOR_PATH="$MVM_PROTECTED_WITNESS_ROOT/absent-libkrun"
unset MVM_SKIP_HASH_VERIFY MVM_SKIP_COSIGN_VERIFY
echo "isolated evidence retained at $MVM_PROTECTED_WITNESS_ROOT"
exec "$MVM_PROTECTED_WITNESS_TEST_BIN" \
    --ignored --exact detached_console_survives_launcher_and_seals_on_stop --nocapture --test-threads=1
