#!/bin/sh
# Install a built mvmctl .deb or .rpm, run what it installed, and remove it.
#
#   distro-package-smoke.sh <package> <version> <payload-sums>
#
# Runs as root inside a throwaway distribution container (distro-packages.yml
# mounts the packages read-only). <payload-sums> is the `sha256sum` manifest
# build-distro-packages.sh wrote from the release tarball, with /usr/bin
# paths, so the check is that the package manager put the tarball's exact
# bytes where mvmctl and the SDKs look for them, not merely that something
# called mvmctl runs.
set -eu

[ $# -eq 3 ] || { sed -n '4p' "$0" | sed 's/^# *//' >&2; exit 2; }
package="$1"
version="$2"
sums="$3"

fail() { echo "distro-package-smoke: $*" >&2; exit 1; }

case "${package}" in
  *.deb)
    format=deb
    apt-get update -qq >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${package}" python3 >/dev/null
    remove() { DEBIAN_FRONTEND=noninteractive apt-get remove -y -qq mvmctl >/dev/null; }
    ;;
  *.rpm)
    format=rpm
    dnf install -y -q "${package}" python3 >/dev/null
    remove() { dnf remove -y -q mvmctl >/dev/null; }
    ;;
  *) fail "not a .deb or .rpm: ${package}" ;;
esac

# Compared by real path: Fedora merged /usr/sbin into /usr/bin and lists
# /usr/sbin first on PATH, so the same file is found under either name.
found="$(command -v mvmctl || true)"
if [ -z "${found}" ] || [ "$(readlink -f "${found}")" != "$(readlink -f /usr/bin/mvmctl)" ]; then
  fail "mvmctl on PATH is ${found:-nothing}, not /usr/bin/mvmctl"
fi
reported="$(mvmctl --version)"
case "${reported}" in
  "mvmctl ${version}"|"mvmctl v${version}") ;;
  *) fail "mvmctl reports '${reported}', not ${version}" ;;
esac
mvmctl --help >/dev/null
sha256sum -c --quiet "${sums}" || fail "installed files differ from the release tarball"
runtime="/usr/lib/mvmctl/guest-runtime/mvm-guest-bins-v${version}.tar.gz"
for suffix in "" .sha256 .bundle .sha256.bundle; do
  [ -s "${runtime}${suffix}" ] || fail "missing paired runtime ${runtime}${suffix}"
done
# Load the installed library, not a build-tree copy. Python is a disposable
# test dependency, not a dependency added to the shipped CLI package.
python3 "$(dirname "$0")/smoke-installed-release.py" /usr "${version}"
# The marker `mvmctl env update` reads to refuse replacing package-owned files.
marker=/usr/share/mvmctl/package-managed
[ "$(cat "${marker}" 2>/dev/null)" = "${format}" ] \
  || fail "${marker} does not name ${format}; mvmctl env update would overwrite the package's files"
echo "installed ${package}: ${reported}; $(wc -l < "${sums}") files match the tarball"

remove
while read -r _ path; do
  [ ! -e "${path}" ] && [ ! -L "${path}" ] || fail "${path} is left behind after removal"
done < "${sums}"
[ ! -e "${marker}" ] || fail "${marker} is left behind after removal"
echo "removed cleanly"
