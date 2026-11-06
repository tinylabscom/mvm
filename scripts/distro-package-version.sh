#!/usr/bin/env bash
# Debian and RPM use `~` to sort a prerelease before the corresponding stable
# release. Neither accepts SemVer's `-` prerelease separator in package Version.
set -euo pipefail

if [ "$#" -ne 1 ] || [ -z "$1" ] || [[ "$1" == v* ]]; then
  echo "distro-package-version: expected a bare nonempty CLI version" >&2
  exit 2
fi
separator='~'
printf '%s\n' "${1//-/$separator}"
