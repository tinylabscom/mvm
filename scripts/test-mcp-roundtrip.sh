#!/usr/bin/env bash
# Plan 32 / Proposal A — `mcp-server-smoke` CI gate.
#
# Spawns `mvmctl mcp stdio` as a child process, drives it through a
# real JSON-RPC roundtrip, and asserts:
#
#   1. `initialize` returns the pinned protocol version + serverInfo.
#   2. `tools/list` returns exactly one tool named `run`.
#   3. `tools/call run` against an unregistered env returns a structured
#      MCP-shaped `isError: true` result (NOT a JSON-RPC error code).
#      This validates the env-allowlist gate without needing a real
#      microVM, and exercises the `tools/call` dispatch path that unit
#      tests can't reach (they use a MockDispatcher).
#   4. Stdout-only-JSON-RPC discipline (cross-cutting "A: stdout-only")
#      under `RUST_LOG=trace` — not a single non-frame byte appears on
#      stdout. mvm-mcp's `init_stderr_tracing` should send everything
#      to stderr.
#
# Usage:
#     scripts/test-mcp-roundtrip.sh                # builds + tests
#     MVMCTL_BIN=./target/debug/mvmctl scripts/test-mcp-roundtrip.sh
#                                                  # skip rebuild
#
# Exit codes:  0 = pass, 1 = assertion failed, 2 = setup error.
#
# Requires `jq` for JSON parsing. CI installs it; locally on macOS
# install via `brew install jq`.

set -euo pipefail

cd "$(dirname "$0")/.."

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

# Three requests, line-framed (one JSON per line, \n-terminated). The
# mvm-mcp stdio loop reads one frame per line.
REQUESTS=$(cat <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"run","arguments":{"env":"__nonexistent_env_for_smoke__","code":"echo hi"}}}
EOF
)

OUT=$(mktemp -t mcp-roundtrip-out.XXXXXX)
ERR=$(mktemp -t mcp-roundtrip-err.XXXXXX)
trap 'rm -f "$OUT" "$ERR"' EXIT

echo "==> running mcp roundtrip (RUST_LOG=trace exercises stdout discipline)"
# RUST_LOG=trace forces the maximum log volume so any leak to stdout
# corrupting JSON-RPC framing shows up. The mcp stdio init should
# install a stderr-only tracing subscriber before any frame is read,
# so trace-level logging lands in $ERR not $OUT.
echo "$REQUESTS" | RUST_LOG=trace "$MVMCTL_BIN" mcp stdio >"$OUT" 2>"$ERR" || true

# --- Assertion 1: stdout has exactly 3 lines, all valid JSON ----------
LINE_COUNT=$(grep -c '^' "$OUT" 2>/dev/null || true)
if [ "$LINE_COUNT" -ne 3 ]; then
    echo "==> FAIL: expected 3 stdout lines, got $LINE_COUNT" >&2
    echo "==> stdout follows:" >&2
    cat "$OUT" >&2
    echo "==> stderr follows:" >&2
    cat "$ERR" >&2
    exit 1
fi

# Validate that every stdout line parses as JSON. Any non-JSON byte
# from `tracing` leaking onto stdout would fail this check.
while IFS= read -r line; do
    if ! echo "$line" | jq -e . >/dev/null 2>&1; then
        echo "==> FAIL: stdout line is not valid JSON: $line" >&2
        echo "==> stderr follows:" >&2
        cat "$ERR" >&2
        exit 1
    fi
done < "$OUT"

# --- Assertion 2: initialize ------------------------------------------
INIT=$(sed -n '1p' "$OUT")
PROTO_VERSION=$(echo "$INIT" | jq -r '.result.protocolVersion // empty')
if [ -z "$PROTO_VERSION" ]; then
    echo "==> FAIL: initialize missing protocolVersion: $INIT" >&2
    exit 1
fi
SERVER_NAME=$(echo "$INIT" | jq -r '.result.serverInfo.name // empty')
if [ "$SERVER_NAME" != "mvm" ]; then
    echo "==> FAIL: initialize serverInfo.name expected 'mvm', got '$SERVER_NAME'" >&2
    exit 1
fi
    # jq's `// empty` treats `false` as falsy, so use `tojson` to
    # reliably distinguish "field present and false" from "missing".
LIST_CHANGED=$(echo "$INIT" | jq -r '.result.capabilities.tools.listChanged | tojson')
if [ "$LIST_CHANGED" != "false" ]; then
    echo "==> FAIL: capabilities.tools.listChanged must be false, got '$LIST_CHANGED'" >&2
    exit 1
fi
echo "    initialize: protocolVersion=$PROTO_VERSION serverInfo.name=$SERVER_NAME"

# --- Assertion 3: tools/list ------------------------------------------
LIST=$(sed -n '2p' "$OUT")
TOOL_COUNT=$(echo "$LIST" | jq -r '.result.tools | length // empty')
if [ "$TOOL_COUNT" != "1" ]; then
    echo "==> FAIL: tools/list expected 1 tool, got $TOOL_COUNT" >&2
    echo "$LIST" >&2
    exit 1
fi
TOOL_NAME=$(echo "$LIST" | jq -r '.result.tools[0].name // empty')
if [ "$TOOL_NAME" != "run" ]; then
    echo "==> FAIL: tools/list expected name 'run', got '$TOOL_NAME'" >&2
    exit 1
fi
# The single-tool design (plan 32 / nix-sandbox-mcp insight) requires
# `env`, `code`, `session`, `close`, `timeout_secs` in the schema.
SCHEMA=$(echo "$LIST" | jq -c '.result.tools[0].inputSchema.properties // empty')
for field in env code session close timeout_secs; do
    if ! echo "$SCHEMA" | jq -e --arg f "$field" '.[$f]' >/dev/null 2>&1; then
        echo "==> FAIL: tools/list schema missing field '$field'" >&2
        echo "    schema: $SCHEMA" >&2
        exit 1
    fi
done
echo "    tools/list: 1 tool ('run'), schema contains env/code/session/close/timeout_secs"

# --- Assertion 4: tools/call against unknown env returns isError ------
# This is the env-allowlist gate. Without an actual microVM template
# named `__nonexistent_env_for_smoke__`, the dispatcher's validate_env
# step should reject the request via a structured ToolResult with
# `isError: true` — NOT a JSON-RPC error frame (which the LLM client
# would retry rather than surface).
CALL=$(sed -n '3p' "$OUT")
HAS_ERROR_FRAME=$(echo "$CALL" | jq -r '.error // empty')
if [ -n "$HAS_ERROR_FRAME" ]; then
    echo "==> FAIL: tools/call against unknown env returned a JSON-RPC error frame," >&2
    echo "    but the contract is a ToolResult with isError=true so the LLM sees the failure." >&2
    echo "    response: $CALL" >&2
    exit 1
fi
IS_ERROR=$(echo "$CALL" | jq -r '.result.isError // empty')
if [ "$IS_ERROR" != "true" ]; then
    echo "==> FAIL: tools/call against unknown env should return isError=true, got '$IS_ERROR'" >&2
    echo "    response: $CALL" >&2
    exit 1
fi
ERR_TEXT=$(echo "$CALL" | jq -r '.result.content[0].text // empty')
if ! echo "$ERR_TEXT" | grep -q "__nonexistent_env_for_smoke__"; then
    echo "==> FAIL: error text should mention the rejected env name, got: $ERR_TEXT" >&2
    exit 1
fi
echo "    tools/call: unknown env rejected via isError=true (text mentions env name)"

# --- Assertion 5: stderr discipline ----------------------------------
# `run_with_dispatcher` emits a sentinel `mvm-mcp stdio loop ready`
# tracing::info line at startup. Asserting that line lands on stderr
# (not stdout) verifies init_stderr_tracing is wired *and* that
# logging::init from `commands/mod.rs::run` is correctly skipped for
# the mcp subcommand. A subscriber that wrote to stdout would be
# caught earlier by the JSON-validity check on every stdout line.
if ! grep -q "mvm-mcp stdio loop ready" "$ERR"; then
    echo "==> FAIL: sentinel 'mvm-mcp stdio loop ready' not found on stderr" >&2
    echo "==> stderr follows:" >&2
    cat "$ERR" >&2
    exit 1
fi
echo "    stderr discipline: sentinel landed on stderr ($(wc -l < "$ERR") lines), stdout stayed clean"

echo "==> ok: mcp roundtrip clean (3/3 assertions pass)"
