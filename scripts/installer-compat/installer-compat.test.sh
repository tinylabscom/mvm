#!/usr/bin/env bash
#
# Tests for the installer compat lanes' scripts.
#
# The lanes themselves need published releases, hosted macOS runners and
# distro containers, so they run only in CI and only on their triggers. What
# decides their verdict does not: which releases are picked, what a release's
# archive obliges an install to produce, which refusal an old release is
# allowed, and what the docs smoke extracts from the page. Those run here,
# against synthetic releases served from a local HTTP server, through the real
# install.sh and uninstall.sh.
#
# Several cases must FAIL. A compat lane that cannot go red is a lane that
# reports green over a broken installer.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."
DIR=scripts/installer-compat

failures=0
work="$(mktemp -d)"
work="$(cd "$work" && pwd -P)"
server_pid=""
cleanup() {
  if [ -n "$server_pid" ]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT

ok() { echo "ok   — $1"; }
bad() {
  echo "FAIL — $1"
  failures=$((failures + 1))
}

# expect_status <want:0|nonzero> <description> <command...>
expect_status() {
  local want="$1" desc="$2" out status
  shift 2
  set +e
  out="$("$@" 2>&1)"
  status=$?
  set -e
  if { [ "$want" = 0 ] && [ "$status" -eq 0 ]; } || { [ "$want" = nonzero ] && [ "$status" -ne 0 ]; }; then
    ok "$desc"
  else
    bad "$desc: expected exit $want, got $status"
    printf '%s\n' "$out" | tail -n 30 | sed 's/^/       /'
  fi
  LAST_OUTPUT="$out"
}

# expect_fails <description> <text the failure must mention> <command...>
# Fails on a zero exit, and on a non-zero exit for some other reason — a lane
# that goes red by accident proves nothing about the check it is meant to make.
expect_fails() {
  local desc="$1" reason="$2"
  shift 2
  expect_status nonzero "$desc" "$@"
  case "$LAST_OUTPUT" in
    *"$reason"*) ;;
    *)
      bad "$desc: the failure does not mention \"$reason\""
      printf '%s\n' "$LAST_OUTPUT" | tail -n 10 | sed 's/^/       /'
      ;;
  esac
}

# expect_eq <description> <want> <got>
expect_eq() {
  if [ "$2" = "$3" ]; then
    ok "$1"
  else
    bad "$1"
    printf '       want: %s\n       got:  %s\n' "$2" "$3"
  fi
}

# --- matrix.sh ----------------------------------------------------------------

asset() { printf '{"name":"%s"}' "$1"; }
release() {
  # release <tag> <published> <prerelease> <draft> <asset names...>
  local tag="$1" published="$2" pre="$3" draft="$4" assets=() name
  shift 4
  for name in "$@"; do assets+=("$(asset "$name")"); done
  printf '{"tag_name":"%s","published_at":"%s","prerelease":%s,"draft":%s,"assets":[%s]}' \
    "$tag" "$published" "$pre" "$draft" "$(IFS=,; echo "${assets[*]}")"
}
linux=mvmctl-x86_64-unknown-linux-gnu.tar.gz
mac=mvmctl-aarch64-apple-darwin.tar.gz
arm=mvmctl-aarch64-unknown-linux-gnu.tar.gz
sums=checksums-sha256.txt

# Two pages, as `gh api --paginate` prints them.
{
  printf '[%s,%s,%s,%s]' \
    "$(release v0.19.0-rc.1 2026-09-20T00:00:00Z true true $sums $linux $mac $arm)" \
    "$(release v0.18.0-rc.1 2026-09-09T00:00:00Z true false $sums $linux $mac $arm)" \
    "$(release boot-image/v0.1.5 2026-09-08T00:00:00Z false false $sums $linux)" \
    "$(release v0.17.0 2026-07-08T00:00:00Z false false $sums $linux $mac $arm)"
  printf '[%s,%s,%s,%s]' \
    "$(release v0.16.1 2026-06-05T00:00:00Z false false $sums $linux $mac)" \
    "$(release v0.15.1 2026-06-03T00:00:00Z false false)" \
    "$(release v0.13.0 2026-04-29T00:00:00Z false false $sums $linux $mac $arm)" \
    "$(release v0.0.1 2026-02-09T00:00:00Z false false mvm-x86_64-unknown-linux-gnu.tar.gz)"
} > "$work/releases.json"

printf 'DEFAULT_VERSION="v0.17.0"\n' > "$work/installer-default"
printf '#!/bin/sh\necho "no baked version here"\n' > "$work/page-without-default"

got="$(sh $DIR/matrix.sh compat "$work/installer-default" 3 \
  ubuntu-latest:x86_64-unknown-linux-gnu macos-latest:aarch64-apple-darwin < "$work/releases.json" \
  | jq -c '[.include[] | "\(.runner) \(.release) \(.strict)"]')"
expect_eq "compat: newest 3 per platform; drafts, boot-image, asset-less and misnamed tags left out; strict from the baked default on" \
  '["ubuntu-latest v0.18.0-rc.1 true","ubuntu-latest v0.17.0 true","ubuntu-latest v0.16.1 false","macos-latest v0.18.0-rc.1 true","macos-latest v0.17.0 true","macos-latest v0.16.1 false"]' \
  "$got"

got="$(sh $DIR/matrix.sh compat "$work/installer-default" 5 \
  ubuntu-24.04-arm:aarch64-unknown-linux-gnu < "$work/releases.json" \
  | jq -c '[.include[] | .release]')"
expect_eq "compat: a release is only picked for a target it publishes an archive for" \
  '["v0.18.0-rc.1","v0.17.0","v0.13.0"]' "$got"

got="$(sh $DIR/matrix.sh upgrade "$work/installer-default" 3 \
  macos-latest:aarch64-apple-darwin < "$work/releases.json" | jq -c '.include[0] | [.releases, .tolerated]')"
expect_eq "upgrade: walks oldest to newest and tolerates only the non-strict releases" \
  '["v0.16.1 v0.17.0 v0.18.0-rc.1","v0.16.1"]' "$got"

printf 'DEFAULT_VERSION="v9.9.9"\n' > "$work/installer-unpublished"
got="$(sh $DIR/matrix.sh compat "$work/installer-unpublished" 2 \
  ubuntu-latest:x86_64-unknown-linux-gnu < "$work/releases.json" 2>/dev/null | jq -c '[.include[] | .strict]')"
expect_eq "compat: an unpublished baked default makes every release strict" '[true,true]' "$got"

got="$(sh $DIR/matrix.sh latest x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu < "$work/releases.json")"
expect_eq "latest: newest full release plus a newer prerelease, both carrying every target" \
  '["v0.17.0","v0.18.0-rc.1"]' "$got"

expect_fails "compat: a platform no release publishes for is an error" \
  "no published release carries mvmctl-x86_64-pc-windows-msvc.tar.gz" \
  sh $DIR/matrix.sh compat "$work/installer-default" 3 windows-latest:x86_64-pc-windows-msvc < "$work/releases.json"
expect_fails "compat: an installer without DEFAULT_VERSION is an error" "has no DEFAULT_VERSION" \
  sh $DIR/matrix.sh compat "$work/page-without-default" 3 ubuntu-latest:x86_64-unknown-linux-gnu < "$work/releases.json"

# The real installer still bakes a version the resolver can read.
expect_status 0 "compat: the checkout's install.sh has a readable DEFAULT_VERSION" \
  sh $DIR/matrix.sh compat install.sh 1 ubuntu-latest:x86_64-unknown-linux-gnu < "$work/releases.json"

# --- synthetic releases -------------------------------------------------------

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) target=aarch64-apple-darwin ;;
  Linux-x86_64) target=x86_64-unknown-linux-gnu ;;
  Linux-aarch64) target=aarch64-unknown-linux-gnu ;;
  *) echo "unsupported host for the synthetic-release tests: $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac
darwin=0
[ "$(uname -s)" = "Darwin" ] && darwin=1

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# fake_mvmctl <reported version> <supports quiesce: yes|no>
fake_mvmctl() {
  cat <<EOF
#!/bin/sh
case "\${1:-}" in
  --version) echo "mvmctl $1" ;;
  doctor) echo "doctor found issues" >&2; exit 1 ;;
  env)
    [ "$2" = yes ] && exit 0
    echo "error: unrecognized subcommand 'env'" >&2
    exit 2
    ;;
esac
EOF
}

# publish <tag> <layout: new|old> <reported version> <quiesce: yes|no>
publish() {
  local tag="$1" layout="$2" reported="$3" quiesce="$4"
  local stage="$work/stage/$tag/mvmctl-$target" out="$work/srv/tinylabscom/mvm/releases/download/$tag"
  mkdir -p "$stage" "$out"
  fake_mvmctl "$reported" "$quiesce" > "$stage/mvmctl"
  printf '#!/bin/sh\nexit 0\n' > "$stage/mvm-network-endpoint"
  printf 'readme\n' > "$stage/README.md"
  chmod 0755 "$stage/mvmctl" "$stage/mvm-network-endpoint"
  if [ "$layout" = new ]; then
    printf '#!/bin/sh\nexit 0\n' > "$stage/mvm-host-agent"
    printf '#!/bin/sh\nexit 0\n' > "$stage/mvm-libkrun-supervisor"
    chmod 0755 "$stage/mvm-host-agent" "$stage/mvm-libkrun-supervisor"
    mkdir -p "$stage/assets" "$stage/man"
    printf '<plist><dict><key>com.apple.security.virtualization</key><true/></dict></plist>\n' \
      > "$stage/assets/mvmctl.entitlements"
    printf '<plist><dict><key>com.apple.security.hypervisor</key><true/></dict></plist>\n' \
      > "$stage/assets/mvm-supervisor.entitlements"
    printf 'man\n' > "$stage/man/mvmctl.1"
  else
    # Pre-assets layouts carried a binary later releases dropped. Some put the
    # entitlement profile under resources/; older fixtures may lack it.
    printf '#!/bin/sh\nexit 0\n' > "$stage/mvm-bridge"
    chmod 0755 "$stage/mvm-bridge"
    if [ "$layout" = old ]; then
      mkdir -p "$stage/resources"
      printf '<plist/>\n' > "$stage/resources/mvmctl.entitlements"
    fi
  fi
  tar czf "$out/mvmctl-$target.tar.gz" -C "$work/stage/$tag" "mvmctl-$target"
  printf '%s  %s\n' "$(sha256 "$out/mvmctl-$target.tar.gz")" "mvmctl-$target.tar.gz" > "$out/checksums-sha256.txt"
}

publish v0.9.0 missing 0.9.0 no
publish v1.0.0 old 1.0.0 no
publish v2.0.0 new 2.0.0 no
publish v2.1.0 new 2.1.0 yes
publish v3.0.0 new 9.9.9 no

# --- archive-facts.sh ---------------------------------------------------------

got="$(sh $DIR/archive-facts.sh "$work/srv/tinylabscom/mvm/releases/download/v2.0.0/mvmctl-$target.tar.gz" "$target" install.sh | tr '\n' ',')"
expect_eq "archive-facts: executables and assets are entries, the installer's exclusions are excluded, profiles listed; README and man/ ignored" \
  "entry assets,entry mvm-host-agent,entry mvm-network-endpoint,entry mvmctl,excluded mvm-libkrun-supervisor,profile mvm-supervisor.entitlements,profile mvmctl.entitlements," \
  "$got"

got="$(sh $DIR/archive-facts.sh "$work/srv/tinylabscom/mvm/releases/download/v1.0.0/mvmctl-$target.tar.gz" "$target" install.sh | tr '\n' ',')"
expect_eq "archive-facts: a resources-layout release carries its profile without an assets entry" \
  "entry mvm-bridge,entry mvm-network-endpoint,entry mvmctl,profile mvmctl.entitlements," "$got"

got="$(sh $DIR/archive-facts.sh "$work/srv/tinylabscom/mvm/releases/download/v0.9.0/mvmctl-$target.tar.gz" "$target" install.sh | tr '\n' ',')"
expect_eq "archive-facts: a release missing every profile reports none" \
  "entry mvm-bridge,entry mvm-network-endpoint,entry mvmctl," "$got"

expect_fails "archive-facts: an archive for another target is refused" "has no mvmctl-other-target/mvmctl" \
  sh $DIR/archive-facts.sh "$work/srv/tinylabscom/mvm/releases/download/v1.0.0/mvmctl-$target.tar.gz" other-target install.sh
expect_fails "archive-facts: an installer with no EXCLUDED_PAYLOADS is refused" "defines no EXCLUDED_PAYLOADS" \
  sh $DIR/archive-facts.sh "$work/srv/tinylabscom/mvm/releases/download/v1.0.0/mvmctl-$target.tar.gz" "$target" "$work/installer-default"

# --- doc-commands.sh ----------------------------------------------------------

cat > "$work/page.md" <<'EOF'
## Install

### One-liner

Some prose.

```bash
curl -fsSL https://example.test/install.sh | sh
```

### Empty section

### Pin a version

```bash
curl -fsSL https://example.test/install.sh | MVM_VERSION=v1.0.0 sh
```
EOF
got="$(sh $DIR/doc-commands.sh "$work/page.md" "### One-liner")"
expect_eq "doc-commands: prints the block under the heading" \
  "curl -fsSL https://example.test/install.sh | sh" "$got"
expect_fails "doc-commands: a missing heading fails" "not found" \
  sh $DIR/doc-commands.sh "$work/page.md" "### Nope"
expect_fails "doc-commands: a heading followed by another heading before any block fails" \
  "has no fenced block before the next heading" \
  sh $DIR/doc-commands.sh "$work/page.md" "### Empty section"

page=public/src/content/docs/install/linux.md
for heading in "### One-liner" "### Pin a version" "## Verify"; do
  expect_status 0 "doc-commands: the Linux install page still has \"$heading\"" \
    sh $DIR/doc-commands.sh "$page" "$heading"
done
pin_block="$(sh $DIR/doc-commands.sh "$page" "### Pin a version")"
# The variable has to reach `sh`, which reads it, not `curl`, which does not:
# `MVM_VERSION=v1 curl … | sh` silently installs the default release.
if printf '%s\n' "$pin_block" | grep -Eq '\|[[:space:]]*MVM_VERSION=[^ ]+[[:space:]]+sh'; then
  ok "doc-commands: the page's pin sets MVM_VERSION on sh"
else
  bad "doc-commands: the page's pin does not set MVM_VERSION on sh: $pin_block"
fi

# --- glibc-requirements.sh ----------------------------------------------------

# Canned `ldd -v` from a Rocky Linux 9 container (glibc 2.34) tracing a binary
# built against glibc 2.39. The libc section requires GLIBC_2.35 of the loader
# itself; that is the library's requirement, not the binary's, and must not be
# reported as the floor.
mkdir -p "$work/lddbin"
printf 'not really elf GLIBC_2.2.5 GLIBC_2.39\n' > "$work/needs-2.39"
tab="$(printf '\t')"
cat > "$work/lddbin/ldd" <<EOF
#!/bin/sh
binary="\${2:-\$1}"
cat <<TRACE
\$binary: /lib64/libc.so.6: version \\\`GLIBC_2.39' not found (required by \$binary)
\$binary: /lib64/libc.so.6: version \\\`GLIBC_2.38' not found (required by \$binary)
${tab}linux-vdso.so.1 (0x00007ffd)
${tab}libc.so.6 => /lib64/libc.so.6 (0x00007f00)

${tab}Version information:
${tab}\$binary:
${tab}${tab}libgcc_s.so.1 (GCC_4.2.0) => /lib64/libgcc_s.so.1
${tab}${tab}libc.so.6 (GLIBC_2.39) => /lib64/libc.so.6
${tab}${tab}libc.so.6 (GLIBC_2.2.5) => /lib64/libc.so.6
${tab}${tab}libc.so.6 (GLIBC_2.38) => /lib64/libc.so.6
${tab}/lib64/libc.so.6:
${tab}${tab}ld-linux-x86-64.so.2 (GLIBC_2.35) => /lib64/ld-linux-x86-64.so.2
${tab}${tab}ld-linux-x86-64.so.2 (GLIBC_PRIVATE) => /lib64/ld-linux-x86-64.so.2
TRACE
EOF
chmod 0755 "$work/lddbin/ldd"
got="$(PATH="$work/lddbin:$PATH" sh $DIR/glibc-requirements.sh "$work/needs-2.39" | tr '\n' ',')"
expect_eq "glibc-requirements: the binary's own floor and each version the loader lacks" \
  "required GLIBC_2.39,missing GLIBC_2.38,missing GLIBC_2.39," "$got"

# A satisfied binary's libraries requiring a higher version than the binary
# does must not raise its floor.
cat > "$work/lddbin/ldd" <<EOF
#!/bin/sh
binary="\${2:-\$1}"
cat <<TRACE
${tab}Version information:
${tab}\$binary:
${tab}${tab}libc.so.6 (GLIBC_2.17) => /lib64/libc.so.6
${tab}/lib64/libc.so.6:
${tab}${tab}ld-linux-x86-64.so.2 (GLIBC_2.35) => /lib64/ld-linux-x86-64.so.2
TRACE
EOF
got="$(PATH="$work/lddbin:$PATH" sh $DIR/glibc-requirements.sh "$work/needs-2.39" | tr '\n' ',')"
expect_eq "glibc-requirements: a library's own requirement is not the binary's floor" \
  "required GLIBC_2.17," "$got"

# No version section at all: fall back to the names in the binary.
printf '#!/bin/sh\necho "not a dynamic executable" >&2\nexit 1\n' > "$work/lddbin/ldd"
got="$(PATH="$work/lddbin:$PATH" sh $DIR/glibc-requirements.sh "$work/needs-2.39" | tr '\n' ',')"
expect_eq "glibc-requirements: with no ldd version section, the strings in the binary decide" \
  "required GLIBC_2.39," "$got"

# --- check-release.sh / check-upgrade.sh against the synthetic releases -------

cat > "$work/serve.py" <<'EOF'
import functools, http.server, os, sys

class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass

server = http.server.ThreadingHTTPServer(
    ("127.0.0.1", 0), functools.partial(Quiet, directory=sys.argv[1]))
with open(sys.argv[2] + ".tmp", "w") as f:
    f.write(str(server.server_address[1]))
os.rename(sys.argv[2] + ".tmp", sys.argv[2])
server.serve_forever()
EOF
python3 "$work/serve.py" "$work/srv" "$work/port" &
server_pid=$!
for _ in $(seq 1 50); do
  [ -s "$work/port" ] && break
  sleep 0.1
done
[ -s "$work/port" ] || { echo "the release server did not start" >&2; exit 1; }
MVM_UPDATE_DOWNLOAD_URL="http://127.0.0.1:$(cat "$work/port")"
export MVM_UPDATE_DOWNLOAD_URL

# codesign stand-in: records the profile a binary was signed with and reports
# it back, so the entitlement assertion is exercised without signing anything.
# Keyed on the physical path, as real codesign reads through the `current` link.
mkdir -p "$work/fakebin" "$work/signatures"
cat > "$work/fakebin/codesign" <<EOF
#!/bin/sh
store="$work/signatures"
physical() { printf '%s/%s' "\$(cd "\$(dirname "\$1")" && pwd -P)" "\$(basename "\$1")" | cksum | cut -d' ' -f1; }
if [ "\$1" = "-d" ]; then
  eval "file=\\\${\$#}"
  key="\$(physical "\$file")"
  [ -f "\$store/\$key" ] || { echo "code object is not signed at all" >&2; exit 1; }
  cat "\$store/\$key"
  exit 0
fi
profile=""
while [ "\$#" -gt 1 ]; do
  [ "\$1" = "--entitlements" ] && profile="\$2"
  shift
done
key="\$(physical "\$1")"
if [ -n "\$profile" ]; then cp "\$profile" "\$store/\$key"; else : > "\$store/\$key"; fi
EOF
chmod 0755 "$work/fakebin/codesign"
export PATH="$work/fakebin:$PATH"
export TMPDIR="$work/tmp"
mkdir -p "$TMPDIR"

expect_status 0 "check-release: a current-layout release installs every entry, leaves the exclusion out, and uninstalls (refused, then --force)" \
  sh $DIR/check-release.sh v2.0.0 "$target" true
case "$LAST_OUTPUT" in
  *"refused, then --force"*) ok "check-release: an uninstall checker that predates --quiesce takes the refuse-then-force path" ;;
  *) bad "check-release: expected the refuse-then-force uninstall path"; printf '%s\n' "$LAST_OUTPUT" | tail -n 5 ;;
esac

expect_status 0 "check-release: a release whose mvmctl supports --quiesce uninstalls without --force" \
  sh $DIR/check-release.sh v2.1.0 "$target" true
case "$LAST_OUTPUT" in
  *"uninstalled (checked)"*) ok "check-release: the checked uninstall path ran" ;;
  *) bad "check-release: expected the checked uninstall path"; printf '%s\n' "$LAST_OUTPUT" | tail -n 5 ;;
esac

expect_fails "check-release: an mvmctl reporting another version fails the lane" \
  "printed 'mvmctl 9.9.9', expected 'mvmctl 3.0.0'" \
  sh $DIR/check-release.sh v3.0.0 "$target" true

if [ "$darwin" = 1 ]; then
  expect_status 0 "check-release (macOS): a resources-layout release installs when strict" \
    sh $DIR/check-release.sh v1.0.0 "$target" true
  expect_status 0 "check-upgrade (macOS): a resources-layout release upgrades without tolerance" \
    sh $DIR/check-upgrade.sh "$target" "v1.0.0 v2.0.0 v2.1.0" ""
  expect_status 0 "check-release (macOS): a release missing its profile may be refused when not strict" \
    sh $DIR/check-release.sh v0.9.0 "$target" false
  expect_fails "check-release (macOS): the missing-profile refusal fails the lane when the release is strict" \
    "its archive has no assets/mvmctl.entitlements" \
    sh $DIR/check-release.sh v0.9.0 "$target" true
  expect_status 0 "check-upgrade (macOS): a refused missing-profile release leaves the upgrade path intact" \
    sh $DIR/check-upgrade.sh "$target" "v0.9.0 v2.0.0 v2.1.0" "v0.9.0"
  expect_fails "check-upgrade (macOS): a missing-profile refusal is not tolerated for an unnamed release" \
    "install.sh failed upgrading an empty prefix to v0.9.0" \
    sh $DIR/check-upgrade.sh "$target" "v0.9.0 v2.0.0 v2.1.0" ""
else
  expect_status 0 "check-release (Linux): an old release installs; no entitlement step applies" \
    sh $DIR/check-release.sh v1.0.0 "$target" true
  expect_status 0 "check-upgrade (Linux): old -> new drops mvm-bridge, keeps history, rolls back and uninstalls" \
    sh $DIR/check-upgrade.sh "$target" "v1.0.0 v2.0.0 v2.1.0" ""
fi
expect_fails "check-upgrade: a release in the walk that reports the wrong version fails it" \
  "printed 'mvmctl 9.9.9', expected 'mvmctl 3.0.0'" \
  sh $DIR/check-upgrade.sh "$target" "v2.0.0 v3.0.0" ""

# --- docs-install-smoke.sh ----------------------------------------------------

# A page shaped like the Linux install page, run against the checkout's
# install.sh through the URL override. The installer's baked default is
# published on the local server so the one-liner has something to install.
baked="$(sed -n 's/^DEFAULT_VERSION="\(.*\)"$/\1/p' install.sh)"
publish "$baked" new "${baked#v}" no

write_page() {
  # write_page <file> <pin command>
  cat > "$1" <<EOF
## Install mvmctl

### One-liner

\`\`\`bash
curl -fsSL https://runmvm.example/install.sh | sh
\`\`\`

### Pin a version

\`\`\`bash
$2
\`\`\`

## Verify

\`\`\`bash
mvmctl doctor
\`\`\`
EOF
}
write_page "$work/good-page.md" "curl -fsSL https://runmvm.example/install.sh | MVM_VERSION=v2.0.0 sh"
write_page "$work/broken-page.md" "MVM_VERSION=v2.0.0 curl -fsSL https://runmvm.example/install.sh | sh"

mkdir -p "$work/smoke-home" "$work/broken-home"
expect_status 0 "docs-install-smoke: the one-liner installs the baked default, the pin installs the pinned release, verify runs" \
  env HOME="$work/smoke-home" CI=true sh $DIR/docs-install-smoke.sh "$work/good-page.md" "file://$PWD/install.sh"
expect_fails "docs-install-smoke: a pin that sets MVM_VERSION on curl instead of sh is caught" \
  "expected 'mvmctl 2.0.0'" \
  env HOME="$work/broken-home" CI=true sh $DIR/docs-install-smoke.sh "$work/broken-page.md" "file://$PWD/install.sh"
expect_fails "docs-install-smoke: refuses to install into \$HOME outside CI" "runs only in CI" \
  env HOME="$work/smoke-home" CI= sh $DIR/docs-install-smoke.sh "$work/good-page.md" "file://$PWD/install.sh"

# The refusal must be for a profile the archive lacks. Plant a log naming one
# the archive carries and confirm it is not taken as an old layout.
if (
  # shellcheck source=scripts/installer-compat/lib.sh
  . $DIR/lib.sh
  printf '[mvm] ERROR: missing entitlement profile: /x/assets/mvmctl.entitlements\n' > "$work/refusal.log"
  if is_tolerated_refusal "$work/refusal.log" "profile mvmctl.entitlements"; then exit 1; fi
  is_tolerated_refusal "$work/refusal.log" "profile mvm-supervisor.entitlements"
  [ "$REFUSED_PROFILE" = mvmctl.entitlements ]
); then
  ok "lib: a refusal is tolerated only when the archive lacks the profile it names"
else
  bad "lib: a refusal is tolerated only when the archive lacks the profile it names"
fi

if (
  # shellcheck source=scripts/installer-compat/lib.sh
  . $DIR/lib.sh
  word_list_contains "v0.17.0 v0.18.0-rc.1" "v0.17.0" || exit 1
  word_list_contains "v0.17.0 v0.18.0-rc.1" "v0.18.0-rc.1" || exit 1
  if word_list_contains "v0.17.0 v0.18.0-rc.1" "v0.18.0"; then exit 1; fi
  if word_list_contains "v0.17.0 v0.18.0-rc.1" "v0.1"; then exit 1; fi
); then
  ok "lib: compatibility baselines match only exact release tags"
else
  bad "lib: compatibility baselines match only exact release tags"
fi

echo
if [ "$failures" -ne 0 ]; then
  echo "$failures installer-compat test(s) failed"
  exit 1
fi
echo "all installer-compat tests passed"
