#!/usr/bin/env bash
# Tests the pre-commit hook's clippy-scoping decision.
#
# The hook narrows `cargo clippy` to the packages owning the staged files. That
# is only sound when cargo can address those packages with `-p`, and several
# real packages in this tree cannot be: `web/mvm-demo/` and every detached fuzz
# crate declare a package name that is not a workspace member. Passing one to
# `cargo -p` exits with "did not match any packages", which the hook reported
# as "clippy failed" — a lint hook claiming a lint failure when lint is fine.
#
# These tests pin the decision, not the clippy run: a fixture workspace, the
# hook's own helper functions, and an assertion on which packages it would
# scope to.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
hook="$repo_root/.githooks/pre-commit"
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT

# Source the hook's helpers without running it. Everything above the
# "Bail out early" guard is definitions; the guard is the first statement that
# acts. If that marker moves, this extraction fails loudly rather than
# silently testing nothing.
fns="$fixture/fns.sh"
sed -n '1,/^# Bail out early/p' "$hook" | sed '$d' > "$fns"
if ! grep -q '^workspace_members()' "$fns"; then
  echo "extraction missed workspace_members — has the 'Bail out early' marker moved?" >&2
  exit 1
fi
if ! grep -q '^owning_package()' "$fns"; then
  echo "extraction missed owning_package" >&2
  exit 1
fi

# A workspace with one member, one non-member sibling, and a detached fuzz
# crate under a member — the three shapes that matter.
mkdir -p "$fixture/ws/crates/real/src" \
         "$fixture/ws/crates/real/fuzz/fuzz_targets" \
         "$fixture/ws/web/demo/src" \
         "$fixture/ws/src"
cat > "$fixture/ws/Cargo.toml" <<'TOML'
[package]
name = "rootpkg"

[workspace]
members = [
    # a comment naming "crates/decoy" must not be read as a member
    "crates/real",
]
TOML
printf '[package]\nname = "realpkg"\n' > "$fixture/ws/crates/real/Cargo.toml"
printf '[package]\nname = "realpkg-fuzz"\n' > "$fixture/ws/crates/real/fuzz/Cargo.toml"
printf '[package]\nname = "demo-web"\n' > "$fixture/ws/web/demo/Cargo.toml"

cd "$fixture/ws"
# shellcheck source=/dev/null
source "$fns"
WORKSPACE_MEMBERS="$(workspace_members)"

expect_member() {
  local file="$1" want_pkg="$2" want_member="$3" pkg verdict
  pkg="$(owning_package "$file")"
  if [ "$pkg" != "$want_pkg" ]; then
    echo "FAIL $file: owning_package said '$pkg', expected '$want_pkg'" >&2
    exit 1
  fi
  if is_workspace_member "$pkg"; then verdict=yes; else verdict=no; fi
  if [ "$verdict" != "$want_member" ]; then
    echo "FAIL $file: is_workspace_member($pkg) said $verdict, expected $want_member" >&2
    exit 1
  fi
  echo "  ok  $file -> $pkg (member: $verdict)"
}

echo "workspace_members:"
printf '%s\n' "$WORKSPACE_MEMBERS" | sed 's/^/  /'

# The root package is addressable even though it is not in `members`.
expect_member "src/lib.rs" "rootpkg" "yes"
# A declared member scopes, which is the whole point of the narrowing.
expect_member "crates/real/src/lib.rs" "realpkg" "yes"
# The two shapes that must widen instead of being handed to `cargo -p`.
expect_member "web/demo/src/lib.rs" "demo-web" "no"
expect_member "crates/real/fuzz/fuzz_targets/t.rs" "realpkg-fuzz" "no"

# A path inside a member but below no nearer manifest still resolves upward.
expect_member "crates/real/src/deep/nested.rs" "realpkg" "yes"

# A member name must not be inferred from a commented-out path.
if is_workspace_member "decoypkg"; then
  echo "FAIL: a name only mentioned in a comment was treated as a member" >&2
  exit 1
fi
echo "  ok  a commented member path is not a member"

echo "pre-commit scoping tests passed"
