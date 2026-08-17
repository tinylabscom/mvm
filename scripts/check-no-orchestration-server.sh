#!/usr/bin/env bash
set -euo pipefail

patterns='\b(axum::Router|axum::serve|axum::Server|hyper::Server|hyper::server::conn|tonic::transport::Server|TcpListener::bind|UnixListener::bind|NamedPipeServer)\b'

strip_cfg_test_modules() {
  awk '
    BEGIN { skip = 0; depth = 0; pending = 0 }
    skip == 1 {
      depth += gsub(/\{/, "&")
      depth -= gsub(/\}/, "&")
      if (depth <= 0) { skip = 0; depth = 0 }
      next
    }
    pending == 1 {
      if ($0 ~ /^[[:space:]]*(pub[[:space:]]+)?mod[[:space:]][^{]*\{/) {
        depth += gsub(/\{/, "&")
        depth -= gsub(/\}/, "&")
        if (depth > 0) { skip = 1 } else { depth = 0 }
        pending = 0
        next
      }
      pending = 0
    }
    /^[[:space:]]*#\[cfg\(test\)\][[:space:]]*$/ { pending = 1; next }
    { print }
  ' "$1"
}

# True when `file` is a module the parent declares under `#[cfg(test)]`.
#
# `strip_cfg_test_modules` already exempts an inline `#[cfg(test)] mod x { .. }`,
# so the same test code was exempt written inline and flagged written as its own
# file. That is an inconsistency in this check, not a policy: a test that binds a
# loopback socket to stand in for an HTTP API is not an orchestration server, and
# where the compiler is told to put it does not change that. This closes the hole
# from the other side by asking the parent module how the file is gated.
declared_cfg_test() {
  local file="$1"
  local dir base parent
  dir=$(dirname "$file")
  base=$(basename "$file" .rs)

  # `foo/tests.rs` is declared by `foo/mod.rs`, or by the sibling `foo.rs`.
  for parent in "$dir/mod.rs" "$(dirname "$dir")/$(basename "$dir").rs"; do
    [[ -f "$parent" ]] || continue
    # The declaration and its attribute are adjacent lines; -B1 pairs them.
    if grep -B1 -E "^[[:space:]]*(pub[[:space:]]+)?mod[[:space:]]+${base}[[:space:]]*;" "$parent" 2>/dev/null \
        | grep -q '#\[cfg(test)\]'; then
      return 0
    fi
  done
  return 1
}

crate_allows_server_patterns() {
  local file="$1"
  local crate_dir cargo_toml
  crate_dir=$(dirname "$file")
  while [[ "$crate_dir" != "." && "$crate_dir" != "/" ]]; do
    cargo_toml="$crate_dir/Cargo.toml"
    if [[ -f "$cargo_toml" ]]; then
      rg -n '^[[:space:]]*substrate_server_category[[:space:]]*=' "$cargo_toml" >/dev/null
      return
    fi
    crate_dir=$(dirname "$crate_dir")
  done
  return 1
}

candidates=$(rg \
  --type rust \
  --files-with-matches \
  --glob '!**/target/**' \
  --glob '!crates/mvm-agentd/**' \
  --glob '!xtask/**' \
  --glob '!**/tests/**' \
  --glob '!**/benches/**' \
  --glob '!**/examples/**' \
  --glob '!**/fuzz/**' \
  --glob '!crates/mvm-build/src/egress_proxy/**' \
  --glob '!crates/mvm-cli/src/commands/shared/vsock.rs' \
  --glob '!crates/mvm-cli/src/commands/vm/forward.rs' \
  --glob '!crates/mvm-cli/src/metrics_server.rs' \
  --glob '!crates/mvm-cli/src/template_cmd.rs' \
  --glob '!crates/deps/libkrun-sys/src/native_gateway.rs' \
  --glob '!crates/mvm-runtime/src/mock_guest_agent.rs' \
  --glob '!crates/mvm-agentd/src/addon_vsock_bridge.rs' \
  --glob '!crates/mvm-runtime/src/qemu.rs' \
  -e "$patterns" \
  crates/ src/ \
  || true)

matches=""
while IFS= read -r file; do
  [[ -z "$file" ]] && continue
  if crate_allows_server_patterns "$file"; then
    continue
  fi
  if declared_cfg_test "$file"; then
    continue
  fi
  hits=$(strip_cfg_test_modules "$file" | grep -nE "$patterns" || true)
  if [[ -n "$hits" ]]; then
    while IFS= read -r hit; do
      matches+="${file}:${hit}"$'\n'
    done <<< "$hits"
  fi
done <<< "$candidates"

if [[ -n "$matches" ]]; then
  echo "::error::A new orchestration server appeared outside the substrate allowlist."
  echo
  echo "$matches"
  echo "Declare a genuine substrate category in the owning Cargo.toml, or move orchestration into mvmd."
  exit 1
fi

echo "No orchestration servers appeared outside the declared substrate categories."
