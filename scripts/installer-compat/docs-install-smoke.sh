#!/bin/sh
# Cold first-run smoke: execute the install and verify commands exactly as the
# Linux install page prints them, on a machine that has never had mvm.
#
#   docs-install-smoke.sh <page.md> [installer-url]
#
# The commands are read out of the page, never retyped here. When an installer
# URL is given, it replaces the documented one and nothing else — that is how a
# pull request runs the page against the install.sh it changes. Without one,
# the page runs against the published installer, as a user's would.
#
# This installs into the real $HOME, so it refuses to run outside CI.
#
# Bootstrap is skipped (MVM_SKIP_BOOTSTRAP=1): preparing the builder VM is what
# the documented-surface e2e lane proves, and it is not a property of the
# install commands.
set -eu

[ "$#" -ge 1 ] && [ "$#" -le 2 ] || { echo "usage: $0 <page.md> [installer-url]" >&2; exit 2; }
PAGE="$1"
OVERRIDE_URL="${2:-}"

# shellcheck disable=SC1091 # lib.sh is shellchecked on its own
. "$(dirname "$0")/lib.sh"

if [ "${CI:-}" != "true" ]; then
  fail "this installs mvmctl into \$HOME/.local; it runs only in CI (CI=true)"
fi

extract() {
  sh "$COMPAT_DIR/doc-commands.sh" "$PAGE" "$1"
}

oneliner="$(extract "### One-liner")"
pinned="$(extract "### Pin a version")"
verify="$(extract "## Verify")"

documented_url="$(printf '%s\n' "$oneliner" | grep -oE 'https://[^ |]+/install\.sh' | sort -u)"
[ "$(printf '%s\n' "$documented_url" | grep -c .)" -eq 1 ] \
  || fail "expected exactly one installer URL in the one-liner, found: $documented_url"
printf '%s\n' "$pinned" | grep -Fq "$documented_url" \
  || fail "the pin-a-version block does not use the one-liner's installer URL"
pin="$(printf '%s\n' "$pinned" | grep -oE 'MVM_VERSION=[^ ]+' | head -n1)"
pin="${pin#MVM_VERSION=}"
[ -n "$pin" ] || fail "the pin-a-version block sets no MVM_VERSION"

url="$documented_url"
if [ -n "$OVERRIDE_URL" ]; then
  url="$OVERRIDE_URL"
  # A literal substitution: no regex metacharacters from either URL are
  # interpreted.
  oneliner="$(printf '%s\n' "$oneliner" | awk -v from="$documented_url" -v to="$url" '
    { out = ""; while ((i = index($0, from)) > 0) { out = out substr($0, 1, i - 1) to; $0 = substr($0, i + length(from)) } print out $0 }')"
  pinned="$(printf '%s\n' "$pinned" | awk -v from="$documented_url" -v to="$url" '
    { out = ""; while ((i = index($0, from)) > 0) { out = out substr($0, 1, i - 1) to; $0 = substr($0, i + length(from)) } print out $0 }')"
fi

installer_copy="$(physical_tmpdir)/install.sh"
curl -fsSL "$url" -o "$installer_copy" || fail "could not fetch the installer from $url"
default="$(sed -n 's/^DEFAULT_VERSION="\(.*\)"$/\1/p' "$installer_copy")"
[ -n "$default" ] || fail "the installer at $url bakes no DEFAULT_VERSION"

bin="$HOME/.local/bin"
[ ! -e "$bin/mvmctl" ] || fail "$bin/mvmctl already exists; this smoke needs a machine without mvm"
export MVM_SKIP_BOOTSTRAP=1

run_block() {
  block_name="$1"
  block="$2"
  say "running the page's \"$block_name\" commands:"
  printf '%s\n' "$block" | sed 's/^/    /'
  bash -eo pipefail -c "$block" || fail "the page's \"$block_name\" commands failed"
}

check_installed() {
  check_want="$(expected_version "$1")"
  check_got="$("$bin/mvmctl" --version 2>&1)" || fail "$bin/mvmctl --version failed after \"$2\": $check_got"
  [ "$check_got" = "$check_want" ] \
    || fail "after \"$2\", mvmctl reports '$check_got', expected '$check_want'"
  say "\"$2\" installed $check_got"
  summary "| $2 | \`$check_got\` |"
}

summary "Installer: \`$url\`"
summary ""
summary "| Page section | Result |"
summary "| --- | --- |"

run_block "One-liner" "$oneliner"
check_installed "$default" "One-liner"

run_block "Pin a version" "$pinned"
check_installed "$pin" "Pin a version"

# The page tells the user to add the install dir to PATH if it is not there.
PATH="$bin:$PATH"
export PATH
set +e
bash -eo pipefail -c "$verify"
verify_status=$?
set -e
case "$verify_status" in
  0|1) say "\"Verify\" ran (exit $verify_status; 1 is doctor reporting host problems)" ;;
  *) fail "the page's \"Verify\" commands exited $verify_status" ;;
esac
summary "| Verify | ran, exit $verify_status |"
