#!/usr/bin/env bash
# Build the .deb and .rpm for one Linux release target from its release
# tarball, so the packages carry the tarball's bytes and nothing rebuilt.
#
#   build-distro-packages.sh <tarball> <target> <version> <out-dir>
#
# <target> is the archive's target name (x86_64-unknown-linux-gnu or
# aarch64-unknown-linux-gnu); it decides the package architecture. <version>
# is the version the packages claim, without a leading `v`. The tarball's
# mvmctl must report it, so a package cannot be labelled with a version its
# contents are not — checked by running mvmctl only when the host can.
#
# The asset lists live in the root Cargo.toml ([package.metadata.deb] and
# [package.metadata.generate-rpm]) and read from target/distro-pkg/, which
# this script fills: bin/ with every file at the top of the archive except the
# README, doc/ with the README, man/ with the man pages, and package-managed/
# with one marker per format, naming it, which each package installs as
# /usr/share/mvmctl/package-managed. Writes into <out-dir>
# the two packages and one `<package>.sha256` per package, the format the
# release's combined checksum manifest is assembled from, plus
# `payload-<target>.sha256sums`: a `sha256sum -c` manifest of the files the
# packages install into /usr/bin, which distro-package-smoke.sh checks the
# installed files against.
#
# Needs cargo-deb and cargo-generate-rpm (`cargo install --locked` at the
# versions distro-packages.yml pins) and runs from the workspace root.
set -euo pipefail

[ $# -eq 4 ] || { sed -n '5p' "$0" | sed 's/^# *//' >&2; exit 2; }
tarball="$1"
target="$2"
version="$3"
out_dir="$4"

case "${target}" in
  x86_64-unknown-linux-gnu)  build_target=x86_64-unknown-linux-musl;  host_arch=x86_64 ;;
  aarch64-unknown-linux-gnu) build_target=aarch64-unknown-linux-musl; host_arch=aarch64 ;;
  *) echo "build-distro-packages: no package for target ${target}" >&2; exit 2 ;;
esac
case "${version}" in
  v*|"") echo "build-distro-packages: version must be bare, got '${version}'" >&2; exit 2 ;;
esac
[ -f "${tarball}" ] || { echo "build-distro-packages: ${tarball} not found" >&2; exit 1; }
if ! { [ -f Cargo.toml ] && grep -q '^\[package\.metadata\.deb\]' Cargo.toml; }; then
  echo "build-distro-packages: run from the workspace root" >&2
  exit 2
fi

stage="target/distro-pkg"
unpack="$(mktemp -d)"
trap 'rm -rf "${unpack}"' EXIT
tar xzf "${tarball}" -C "${unpack}"
src="${unpack}/mvmctl-${target}"
[ -x "${src}/mvmctl" ] || { echo "build-distro-packages: ${tarball} has no mvmctl-${target}/mvmctl" >&2; exit 1; }

if [ "$(uname -s)/$(uname -m)" = "Linux/${host_arch}" ]; then
  reported="$("${src}/mvmctl" --version)"
  case "${reported}" in
    *"${version}"*) ;;
    *) echo "build-distro-packages: mvmctl reports '${reported}', not ${version}" >&2; exit 1 ;;
  esac
fi

rm -rf "${stage}"
mkdir -p "${stage}/bin" "${stage}/doc" "${stage}/man" "${stage}/package-managed"
find "${src}" -maxdepth 1 -type f ! -name README.md -exec cp -p {} "${stage}/bin/" \;
cp -p "${src}/README.md" "${stage}/doc/"
cp -p "${src}"/man/*.1 "${stage}/man/"
printf '%s\n' deb > "${stage}/package-managed/deb"
printf '%s\n' rpm > "${stage}/package-managed/rpm"

# Reproducible payload timestamps: the commit being packaged, not the clock.
SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
export SOURCE_DATE_EPOCH

mkdir -p "${out_dir}"
# --no-strip: the packaged binaries must stay byte-identical to the tarball's,
# whose digests the signed manifest already records.
deb="$(cargo deb --no-build --no-strip --target "${build_target}" \
  --deb-version "${version}-1" --output "${out_dir}" | tail -n 1)"
rpm_dir="$(mktemp -d)"
trap 'rm -rf "${unpack}" "${rpm_dir}"' EXIT
cargo generate-rpm --target "${build_target}" --auto-req disabled \
  --set-metadata "version = \"${version}\"" --output "${rpm_dir}/"
rpms=("${rpm_dir}"/*.rpm)
[ "${#rpms[@]}" -eq 1 ] || { echo "build-distro-packages: expected one .rpm, got ${rpms[*]}" >&2; exit 1; }
cp "${rpms[0]}" "${out_dir}/"
rpm="${out_dir}/$(basename "${rpms[0]}")"

( cd "${stage}/bin" && for f in *; do
    printf '%s  /usr/bin/%s\n' "$(shasum -a 256 "$f" | cut -d' ' -f1)" "$f"
  done ) > "${out_dir}/payload-${target}.sha256sums"

for package in "${deb}" "${rpm}"; do
  [ -f "${package}" ] || { echo "build-distro-packages: ${package} was not written" >&2; exit 1; }
  ( cd "$(dirname "${package}")" && shasum -a 256 "$(basename "${package}")" > "$(basename "${package}").sha256" )
  echo "built ${package}"
done
