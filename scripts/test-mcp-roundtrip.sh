#!/bin/sh
set -eu

# Named no-boot consumer for the MCP surface. It performs discovery, catalog
# listing, and the read-only facade capability call in one stdio process.
mcp_bin=${MVM_MCP_BIN:-target/debug/mvmctl}
if [ ! -x "$mcp_bin" ]; then
  echo "MCP binary is not executable: $mcp_bin" >&2
  exit 2
fi

output_file=$(mktemp)
meta='{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"mvm-roundtrip","version":"1"}}'
input_file=$(mktemp)
trap 'rm -f "$input_file" "$output_file"' EXIT
{
  printf '{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":%s}}\n' "$meta"
  printf '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":%s}}\n' "$meta"
  printf '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"_meta":%s,"name":"mvm.backend_capabilities","arguments":{}}}\n' "$meta"
} >"$input_file"

if [ "${MVM_MCP_DIRECT:-0}" = 1 ]; then
  "$mcp_bin" <"$input_file" >"$output_file"
else
  "$mcp_bin" ops mcp stdio <"$input_file" >"$output_file"
fi

if [ "$(wc -l <"$output_file")" -ne 3 ]; then
  echo "MCP roundtrip returned an unexpected response count" >&2
  exit 1
fi
sed -n '1p' "$output_file" | grep -Fq '"supportedVersions":["2026-07-28"'
sed -n '2p' "$output_file" | grep -Fq '"name":"mvm.backend_capabilities"'
sed -n '3p' "$output_file" | grep -Fq '"isError":false'
sed -n '3p' "$output_file" | grep -Fq '"kind":"'

echo "MCP stdio roundtrip passed (discovery, catalog, facade capabilities)"
