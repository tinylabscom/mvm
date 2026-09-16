#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <installer-url>" >&2
  exit 2
fi

probe_dir="$(mktemp -d)"
trap 'rm -f "$probe_dir/body" "$probe_dir/headers"; rmdir "$probe_dir"' EXIT HUP INT TERM

status="$(curl --silent --show-error --location \
  --output "$probe_dir/body" --dump-header "$probe_dir/headers" \
  --write-out '%{http_code}' "$1")"
content_type="$(awk 'BEGIN { IGNORECASE=1 } /^content-type:/ { value=$0 } END { sub(/^[^:]*:[[:space:]]*/, "", value); sub(/\r$/, "", value); print value }' "$probe_dir/headers")"

if [ "$status" != "200" ]; then
  printf 'expected HTTP 200, got %s\n' "$status" >&2
  exit 1
fi

case "$content_type" in
  text/x-shellscript*) ;;
  *)
    printf 'expected text/x-shellscript content type, got %s\n' "$content_type" >&2
    exit 1
    ;;
esac

if ! grep -Fq '# mvmctl installer.' "$probe_dir/body"; then
  echo 'installer marker is missing' >&2
  exit 1
fi

printf 'ok   %s — published installer is healthy\n' "$1"
