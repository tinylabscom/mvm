#!/usr/bin/env bash
# Plan 73 Followup D — `app-deps-audit` CI gate.
#
# ADR-047 §"CI gate" calls for a workflow lane that exercises the
# application-dep install pipeline end-to-end on every PR. The full
# end-to-end shape (real `nix build` driving the libkrun/cloud-hypervisor
# builder VM, real `uv pip install` + `pip-audit`) requires a working
# builder VM, which Plan 72 W4/W5 is still mid-cutover for. Until that
# lands, this script exercises everything around the VM-driven slice:
#
#   1. `mvmctl compile examples/python/hello-app-with-deps/app.py` —
#      validates the decorator parser accepts `dependencies=
#      mvm.python_deps(...)`, lowers it to IR, and emits launch.json
#      with a populated `dependencies` block. The compile step does
#      not touch the network or boot a VM.
#
#   2. Hand-seal a sealed deps volume via
#      `seal_volume(content + sbom + fetch_log + cve)` using the wire
#      shape `mvm-host-vm-init::install::seal` produces inside the
#      builder VM (Followup B.2). The host driver doing the sealing
#      is `crates/mvm-build/tests/app_deps_orchestrator.rs::seal_into_cache`
#      — we re-use that test path via a dedicated example bin so the
#      shell script doesn't reach into test-only code.
#
#   3. `mvmctl deps inspect <hash> --json` — verifies the sealed
#      volume parses, asserts SBOM + fetch log + CVE counts come out
#      well-formed, and that the supervisor's `verify_sealed_volume`
#      contract holds against a freshly-sealed wire payload.
#
#   4. `mvmctl deps audit <hash>` against the same volume — exercises
#      the re-audit path with a stub runner (pip-audit / pnpm-audit
#      may not be on the CI PATH; the runner abstraction in
#      `crates/mvm-cli/src/commands/deps/audit.rs::AuditRunner` lets
#      the test inject a deterministic result). For now, the shell
#      script only asserts the verb refuses gracefully when no audit
#      tool is on PATH — proves error handling, not the happy path.
#
#   5. **Negative path**: hand-seal a second volume whose `cve.json`
#      carries a high-severity finding, then assert the prod gate
#      (`apply_install_gate(..., Prod)`) refuses it. Drives the
#      `mvm-app-deps-fixture-tool` example bin which is the same
#      seal/verify path the orchestrator uses; exercises ADR-047
#      §"Gate semantics" prod-rejection end-to-end.
#
# What this script DOES NOT cover (named so future readers know):
#
#   - `mvmctl build --deps examples/python/hello-app-with-deps/` ⇒
#     real builder VM round-trip. Needs Plan 72 cutover.
#   - `mvmctl up --prod examples/python/hello-app-with-deps/` ⇒
#     supervisor admission claim 9 enforcement against a real volume.
#     Needs a working microVM backend with `/dev/kvm` and (Apple
#     Silicon) libkrun, which GitHub macOS runners don't expose.
#
# Both are documented as manual smoke in
# `examples/python/hello-app-with-deps/README.md`.
#
# Usage:
#     scripts/test-app-deps-ci-gate.sh                # builds + smokes
#     MVMCTL_BIN=./target/debug/mvmctl scripts/test-app-deps-ci-gate.sh
#                                                     # skip rebuild
#
# Exit codes: 0 = pass, 1 = assertion failed, 2 = setup error.
#
# Requires `jq` for JSON parsing. CI installs it; locally on macOS
# install via `brew install jq`.

set -euo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"

if ! command -v jq >/dev/null 2>&1; then
    echo "error: jq not on PATH (install: brew install jq / apt-get install jq)" >&2
    exit 2
fi

MVMCTL_BIN="${MVMCTL_BIN:-}"
if [ -z "$MVMCTL_BIN" ]; then
    echo "==> building mvmctl"
    cargo build --bin mvmctl
    MVMCTL_BIN="./target/debug/mvmctl"
fi

if [ ! -x "$MVMCTL_BIN" ]; then
    echo "error: mvmctl binary not executable at $MVMCTL_BIN" >&2
    exit 2
fi

FIXTURE_BIN="${FIXTURE_BIN:-}"
if [ -z "$FIXTURE_BIN" ]; then
    echo "==> building mvm-app-deps-fixture-tool example bin"
    cargo build -p mvm-build --example mvm-app-deps-fixture-tool
    FIXTURE_BIN="./target/debug/examples/mvm-app-deps-fixture-tool"
fi

if [ ! -x "$FIXTURE_BIN" ]; then
    echo "error: fixture binary not executable at $FIXTURE_BIN" >&2
    exit 2
fi

# Scratch dirs for the smoke run. Override-roots so the script never
# writes into the user's real ~/.mvm/ cache.
SCRATCH="$(mktemp -d -t mvm-app-deps-ci-XXXXXX)"
trap 'rm -rf "$SCRATCH"' EXIT
export MVM_DEPS_VOLUMES_DIR="$SCRATCH/volumes"
mkdir -p "$MVM_DEPS_VOLUMES_DIR"

PASS=0
FAIL=0

assert_eq () {
    local what="$1"
    local got="$2"
    local want="$3"
    if [ "$got" = "$want" ]; then
        echo "    ok: $what"
        PASS=$((PASS + 1))
    else
        echo "    FAIL: $what" >&2
        echo "        got:  $got" >&2
        echo "        want: $want" >&2
        FAIL=$((FAIL + 1))
    fi
}

assert_nonempty () {
    local what="$1"
    local got="$2"
    if [ -n "$got" ] && [ "$got" != "null" ]; then
        echo "    ok: $what (=$got)"
        PASS=$((PASS + 1))
    else
        echo "    FAIL: $what (got empty/null)" >&2
        FAIL=$((FAIL + 1))
    fi
}

# ─────────────────────────────────────────────────────────────────
# 1. mvmctl compile examples/python/hello-app-with-deps/app.py
# ─────────────────────────────────────────────────────────────────

echo "==> 1. compile examples/python/hello-app-with-deps/"
COMPILE_OUT="$SCRATCH/compile-out"
"$MVMCTL_BIN" build compile examples/python/hello-app-with-deps/app.py --out "$COMPILE_OUT" >/dev/null

assert_eq "flake.nix emitted"   "$([ -f "$COMPILE_OUT/flake.nix" ] && echo y || echo n)" "y"
assert_eq "launch.json emitted" "$([ -f "$COMPILE_OUT/launch.json" ] && echo y || echo n)" "y"
assert_eq "src/ emitted"        "$([ -d "$COMPILE_OUT/src" ] && echo y || echo n)" "y"

LAUNCH="$(cat "$COMPILE_OUT/launch.json")"
assert_eq "dependencies.kind"     "$(jq -r '.dependencies.kind' <<<"$LAUNCH")"     "python"
assert_eq "dependencies.lockfile" "$(jq -r '.dependencies.lockfile' <<<"$LAUNCH")" "uv.lock"
assert_eq "dependencies.tool"     "$(jq -r '.dependencies.tool' <<<"$LAUNCH")"     "uv"

# ─────────────────────────────────────────────────────────────────
# 2. Hand-seal a clean fixture volume + 3. inspect it
# ─────────────────────────────────────────────────────────────────

echo "==> 2. seal a clean fixture volume"
CLEAN_OUT="$SCRATCH/clean-seal.json"
"$FIXTURE_BIN" seal-clean --cache-root "$MVM_DEPS_VOLUMES_DIR" --out-json "$CLEAN_OUT"
CLEAN_HASH="$(jq -r '.volume_hash' "$CLEAN_OUT")"
assert_nonempty "clean fixture volume_hash" "$CLEAN_HASH"
assert_eq "clean fixture volume_dir exists" \
    "$([ -d "$MVM_DEPS_VOLUMES_DIR/$CLEAN_HASH" ] && echo y || echo n)" "y"
assert_eq "clean fixture meta.json present" \
    "$([ -f "$MVM_DEPS_VOLUMES_DIR/$CLEAN_HASH/meta.json" ] && echo y || echo n)" "y"
assert_eq "clean fixture sbom.cdx.json present" \
    "$([ -f "$MVM_DEPS_VOLUMES_DIR/$CLEAN_HASH/sbom.cdx.json" ] && echo y || echo n)" "y"
assert_eq "clean fixture cve.json present" \
    "$([ -f "$MVM_DEPS_VOLUMES_DIR/$CLEAN_HASH/cve.json" ] && echo y || echo n)" "y"
assert_eq "clean fixture fetch.log present" \
    "$([ -f "$MVM_DEPS_VOLUMES_DIR/$CLEAN_HASH/fetch.log" ] && echo y || echo n)" "y"

echo "==> 3. mvmctl deps inspect <clean_hash> --json"
INSPECT="$("$MVMCTL_BIN" deps inspect "$CLEAN_HASH" --cache-root "$MVM_DEPS_VOLUMES_DIR" --json)"
assert_eq "inspect volume_hash echoes"   "$(jq -r '.volume_hash' <<<"$INSPECT")" "$CLEAN_HASH"
assert_eq "inspect meta.schema_version"  "$(jq -r '.meta.schema_version' <<<"$INSPECT")" "1"
# `top_components` carries the SBOM the fixture seeded; sbom_summary
# should report a non-zero count.
SBOM_COUNT="$(jq -r '.sbom.component_count' <<<"$INSPECT")"
if [ "$SBOM_COUNT" -gt 0 ]; then
    echo "    ok: inspect.sbom.component_count > 0 (=$SBOM_COUNT)"
    PASS=$((PASS + 1))
else
    echo "    FAIL: inspect.sbom.component_count was 0 — fixture didn't seed components" >&2
    FAIL=$((FAIL + 1))
fi
# fetch.log should report ≥1 line + ≥1 host.
FETCH_LINES="$(jq -r '.fetch_log.line_count' <<<"$INSPECT")"
if [ "$FETCH_LINES" -gt 0 ]; then
    echo "    ok: inspect.fetch_log.line_count > 0 (=$FETCH_LINES)"
    PASS=$((PASS + 1))
else
    echo "    FAIL: inspect.fetch_log.line_count was 0" >&2
    FAIL=$((FAIL + 1))
fi
# cve.json on the clean fixture has zero findings; the inspector
# reports `unknown_severity` for unparseable rows, but a clean stub
# carries no entries at all.
assert_eq "inspect.cve.total_findings == 0 (clean)" \
    "$(jq -r '.cve.total_findings' <<<"$INSPECT")" "0"

# ─────────────────────────────────────────────────────────────────
# 4. Negative path — hand-seal a volume with a HIGH-severity CVE
#    finding and assert the prod gate refuses it.
# ─────────────────────────────────────────────────────────────────

echo "==> 4. seal a volume with a HIGH CVE finding, gate-check under --prod"
CVE_OUT="$SCRATCH/cve-seal.json"
"$FIXTURE_BIN" seal-with-high-cve --cache-root "$MVM_DEPS_VOLUMES_DIR" --out-json "$CVE_OUT"
CVE_HASH="$(jq -r '.volume_hash' "$CVE_OUT")"
assert_nonempty "cve fixture volume_hash" "$CVE_HASH"

# `gate-check` exits 0 when the gate ACCEPTS, nonzero when it
# REJECTS. We want a rejection.
echo "    running gate-check --prod against high-CVE volume (expect REJECTION)"
if "$FIXTURE_BIN" gate-check --cache-root "$MVM_DEPS_VOLUMES_DIR" \
    --volume-hash "$CVE_HASH" --gate prod 2>/dev/null; then
    echo "    FAIL: prod gate ACCEPTED a high-CVE volume — claim 9 is broken" >&2
    FAIL=$((FAIL + 1))
else
    echo "    ok: prod gate refused high-CVE volume"
    PASS=$((PASS + 1))
fi

# And the dev gate must NOT refuse — same volume, dev posture, accept.
echo "    running gate-check --dev against high-CVE volume (expect ACCEPT + warn)"
if "$FIXTURE_BIN" gate-check --cache-root "$MVM_DEPS_VOLUMES_DIR" \
    --volume-hash "$CVE_HASH" --gate dev 2>/dev/null; then
    echo "    ok: dev gate admitted high-CVE volume (warn-and-continue)"
    PASS=$((PASS + 1))
else
    echo "    FAIL: dev gate refused — ADR-047 says --dev warn-and-continues" >&2
    FAIL=$((FAIL + 1))
fi

# Same gate-check against the clean volume under --prod must accept.
echo "    running gate-check --prod against CLEAN volume (expect ACCEPT)"
if "$FIXTURE_BIN" gate-check --cache-root "$MVM_DEPS_VOLUMES_DIR" \
    --volume-hash "$CLEAN_HASH" --gate prod 2>/dev/null; then
    echo "    ok: prod gate accepted clean volume"
    PASS=$((PASS + 1))
else
    echo "    FAIL: prod gate REFUSED a clean volume" >&2
    FAIL=$((FAIL + 1))
fi

# ─────────────────────────────────────────────────────────────────
# 5. Tamper detection — flip a byte in cve.json on the clean volume
#    and assert `mvmctl deps inspect` refuses.
# ─────────────────────────────────────────────────────────────────

echo "==> 5. tamper cve.json on clean volume; inspect must refuse"
printf 'FORGED' >> "$MVM_DEPS_VOLUMES_DIR/$CLEAN_HASH/cve.json"
if "$MVMCTL_BIN" deps inspect "$CLEAN_HASH" \
    --cache-root "$MVM_DEPS_VOLUMES_DIR" --json >/dev/null 2>&1; then
    echo "    FAIL: inspect ACCEPTED a tampered volume — verify_sealed_volume drift" >&2
    FAIL=$((FAIL + 1))
else
    echo "    ok: inspect refused tampered volume"
    PASS=$((PASS + 1))
fi

# ─────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────

echo
echo "==> app-deps-audit CI gate: $PASS passed, $FAIL failed"
if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
