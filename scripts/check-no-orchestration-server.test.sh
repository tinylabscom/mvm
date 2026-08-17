#!/usr/bin/env bash
#
# Gate tests for check-no-orchestration-server.sh.
#
# The gate answers one question — "is this server compiled into a shipped
# binary?" — and both wrong answers are expensive. A false positive blocks a
# legitimate test fixture that binds an ephemeral loopback port. A false
# negative lets a real orchestration server into the CLI, which is the thing
# the gate exists to prevent.
#
# So each case here asserts a direction, and the refusal cases matter more
# than the acceptance ones: a gate that only ever passes is indistinguishable
# from a gate that is not running.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
GATE=scripts/check-no-orchestration-server.sh
PROBE=crates/mvm-cli/src/commands/__gate_probe

failures=0

cleanup() { rm -rf "$PROBE"; }
trap cleanup EXIT

# Runs the gate against a probe module and asserts the outcome.
#   expect_gate <accept|refuse> <description> <parent-mod-source>
expect_gate() {
  local expect="$1" desc="$2" parent="$3"
  mkdir -p "$PROBE"
  printf 'pub fn serve() { let _l = std::net::TcpListener::bind("0.0.0.0:8080"); }\n' \
    > "$PROBE/tests.rs"
  printf '%s\n' "$parent" > "$PROBE/mod.rs"

  local got
  if bash "$GATE" >/dev/null 2>&1; then got=accept; else got=refuse; fi
  rm -rf "$PROBE"

  if [[ "$got" == "$expect" ]]; then
    echo "ok   — $desc"
  else
    echo "FAIL — $desc (expected to $expect, did $got)"
    failures=$((failures + 1))
  fi
}

# The regression this file was written for: `#[cfg(test)] mod tests;` puts the
# body in its own file, which carries no marker of its own. Before the parent
# declaration was resolved, every line of it read as production code.
expect_gate accept "out-of-line cfg(test) module may bind a listener" \
  '#[cfg(test)]
mod tests;'

# The same bytes in the same filename, compiled for real. Exempting by name
# rather than by whether the tree builds it would pass this, which is why the
# gate resolves the declaration instead.
expect_gate refuse "a listener in tests.rs is caught when the parent ships it" \
  'mod tests;'

# `pub mod` under cfg(test) is still test-only.
expect_gate accept "pub mod form of the out-of-line cfg(test) declaration" \
  '#[cfg(test)]
pub mod tests;'

# A cfg that is not `test` grants no exemption.
expect_gate refuse "a non-test cfg does not exempt the module" \
  '#[cfg(feature = "extra")]
mod tests;'

# The gate must still see servers in ordinary production files.
mkdir -p "$PROBE"
printf 'pub fn serve() { let _l = std::net::TcpListener::bind("0.0.0.0:8080"); }\n' \
  > "$PROBE/mod.rs"
if bash "$GATE" >/dev/null 2>&1; then
  echo "FAIL — a listener in a plain production module (expected to refuse, did accept)"
  failures=$((failures + 1))
else
  echo "ok   — a listener in a plain production module is refused"
fi
rm -rf "$PROBE"

# Without ripgrep the gate examined nothing and said so with exit 0. That is
# the failure this suite exists to catch in general form: a check that cannot
# run must not report success, because a green tick is read as evidence the
# thing was looked at. Reproduced by running with a PATH that has no `rg`.
# PATH must stay otherwise intact: emptying it removes coreutils too, and the
# gate then fails for the wrong reason — which looks like a pass for this
# assertion while proving nothing about ripgrep. So drop only the directory
# ripgrep lives in.
rg_dir=$(dirname "$(command -v rg)")
path_without_rg=$(printf '%s' "$PATH" | tr ':' '\n' | grep -vxF "$rg_dir" | paste -sd: -)
if PATH="$path_without_rg" bash "$GATE" >/dev/null 2>&1; then
  echo "FAIL — the gate reports success when ripgrep is unavailable"
  failures=$((failures + 1))
else
  echo "ok   — the gate refuses to pass when ripgrep is unavailable"
fi

# And the tree as it stands must pass, or the gate is red for everyone.
if bash "$GATE" >/dev/null 2>&1; then
  echo "ok   — the working tree passes the gate"
else
  echo "FAIL — the working tree does not pass the gate"
  failures=$((failures + 1))
fi

if [[ "$failures" -gt 0 ]]; then
  echo
  echo "$failures gate test(s) failed."
  exit 1
fi
echo
echo "All orchestration-server gate tests passed."
