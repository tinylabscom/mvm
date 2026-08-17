#!/usr/bin/env bash
set -euo pipefail

# The whole gate is one `rg` invocation whose miss is indistinguishable from a
# clean tree, and the call site swallows a failure with `|| true` so a genuine
# search error cannot be told from "nothing matched". Without `rg` installed
# the script therefore reports success having examined nothing — a gate that
# passes vacuously, which is worse than no gate because it reads as evidence.
if ! command -v rg >/dev/null 2>&1; then
  echo "::error::ripgrep (rg) is not installed; this gate cannot examine anything." >&2
  echo "Install it in the job that runs this script rather than letting the check pass unexamined." >&2
  exit 1
fi

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

# True when the file is a module the tree only compiles under `cfg(test)`.
#
# `strip_cfg_test_modules` handles the inline form — `#[cfg(test)] mod tests {
# .. }` — by scanning the file itself. It cannot see the out-of-line form,
# where `#[cfg(test)] mod tests;` sits in the parent and the body lives in its
# own file: that file carries no marker of its own, so every line in it read as
# production code. A test binding an ephemeral loopback port then looks exactly
# like a new orchestration server.
#
# Resolving the declaration keeps the gate's meaning ("is this compiled into a
# shipped binary?") rather than trusting a filename, so a real server in a file
# called `tests.rs` is still caught unless its parent gates it out of the build.
file_is_out_of_line_cfg_test_module() {
  local file="$1"
  local dir base parent name
  dir=$(dirname "$file")
  base=$(basename "$file" .rs)

  if [[ "$base" == "mod" ]]; then
    # `foo/mod.rs` is declared as `mod foo;` one level up.
    name=$(basename "$dir")
    dir=$(dirname "$dir")
  else
    name="$base"
  fi

  for parent in "$dir.rs" "$dir/mod.rs" "$dir/lib.rs" "$dir/main.rs"; do
    [[ -f "$parent" ]] || continue
    if awk -v want="$name" '
      /^[[:space:]]*#\[cfg\(test\)\][[:space:]]*$/ { pending = 1; next }
      pending == 1 && $0 ~ "^[[:space:]]*(pub[[:space:]]+)?mod[[:space:]]+" want "[[:space:]]*;" { found = 1; exit }
      { pending = 0 }
      END { exit !found }
    ' "$parent"; then
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
  if file_is_out_of_line_cfg_test_module "$file"; then
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
