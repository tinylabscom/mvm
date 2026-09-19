#!/bin/sh
# What glibc a Linux binary needs, and which of those versions this system's
# loader cannot supply. Does not execute the binary.
#
#   glibc-requirements.sh <binary>
#
# Prints:
#
#   required GLIBC_x.y   the highest version the binary itself requires
#   missing GLIBC_x.y    one line per version the loader reports not found
#
# The requirement is read from the binary's own section of `ldd -v`; the
# sections after it list what its libraries require, which is not the
# binary's floor. When the loader prints no version section at all, the
# version names are read out of the binary as strings instead.
set -eu

[ "$#" -eq 1 ] || { echo "usage: $0 <binary>" >&2; exit 2; }
binary="$1"

trace="$(ldd -v "$binary" 2>&1 || true)"

required="$(printf '%s\n' "$trace" | awk -v me="$binary:" '
  /^\t[^\t]/ { mine = ($1 == me) }
  mine {
    line = $0
    while (match(line, /GLIBC_[0-9]+(\.[0-9]+)+/)) {
      print substr(line, RSTART, RLENGTH)
      line = substr(line, RSTART + RLENGTH)
    }
  }
' | sort -u -V | tail -n1)"
if [ -z "$required" ]; then
  required="$(grep -ao 'GLIBC_[0-9][0-9.]*[0-9]' "$binary" | sort -u -V | tail -n1 || true)"
fi
if [ -n "$required" ]; then
  printf 'required %s\n' "$required"
fi

printf '%s\n' "$trace" | grep -o "GLIBC_[0-9.]*' not found" | sed "s/' not found//" | sort -u -V \
  | sed 's/^/missing /' || true
