#!/usr/bin/env bash
# Asserts a *deployed* site actually sends the cross-origin isolation headers
# the WebLinux demo needs. QEMU-Wasm uses pthreads, so it needs
# SharedArrayBuffer, which browsers expose only to a cross-origin-isolated
# document — and isolation does not propagate upward from a frame, so the page
# embedding the demo has to be isolated too, not just the demo document.
#
# This checks the wire, not the repo, because the repo has been right while the
# wire was wrong: `public/public/_headers` is a Cloudflare Pages file that
# GitHub Pages silently ignores, so a correct config served by the wrong host —
# or by the right host behind DNS that still points at the old one — produces
# exactly the shipped-and-broken state, with nothing in the tree to show for
# it. `pnpm check:headers` gates the config; this gates the deployment.
#
# Usage: check-site-isolation-headers.sh [base-url] [path ...]
# The base URL defaults to the site config's own domain, and the paths to the
# landing page and the demo document.
set -euo pipefail

readonly WANT_COOP="same-origin"
readonly WANT_COEP="require-corp"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly REPO_ROOT

# One source of truth for the domain: a copy pinned here would keep passing
# against the old one after a domain move.
site_url_from_config() {
  local config="$REPO_ROOT/public/astro.config.mjs" url
  url=$(sed -n 's/^[[:space:]]*site:[[:space:]]*"\([^"]*\)".*/\1/p' "$config" | head -n 1)
  if [[ -z "$url" ]]; then
    echo "could not read the site URL from $config" >&2
    return 1
  fi
  printf '%s' "$url"
}

# Header names are case-insensitive on the wire; take the last occurrence and
# strip the name, surrounding whitespace, and the trailing CR.
header_value() {
  local headers="$1" name="$2"
  printf '%s\n' "$headers" |
    grep -i "^${name}:" |
    tail -n 1 |
    sed -e 's/^[^:]*:[[:space:]]*//' -e 's/[[:space:]]*$//'
}

# A just-published deployment can take a moment to become reachable, and a
# transient fetch failure must not be reported as a missing header.
fetch_headers() {
  local url="$1" attempt response
  for attempt in 1 2 3 4 5; do
    if response=$(curl --silent --show-error --location --fail --max-time 30 --head "$url"); then
      printf '%s' "$response"
      return 0
    fi
    if [[ "$attempt" -lt 5 ]]; then
      sleep $((attempt * 5))
    fi
  done
  return 1
}

check_url() {
  local url="$1" headers got_coop got_coep ok=1

  if ! headers=$(fetch_headers "$url"); then
    echo "FAIL $url — could not fetch" >&2
    return 1
  fi

  got_coop=$(header_value "$headers" "cross-origin-opener-policy")
  got_coep=$(header_value "$headers" "cross-origin-embedder-policy")

  if [[ "$got_coop" != "$WANT_COOP" ]]; then
    echo "FAIL $url — Cross-Origin-Opener-Policy: want '$WANT_COOP', got '${got_coop:-nothing}'" >&2
    ok=0
  fi
  if [[ "$got_coep" != "$WANT_COEP" ]]; then
    echo "FAIL $url — Cross-Origin-Embedder-Policy: want '$WANT_COEP', got '${got_coep:-nothing}'" >&2
    ok=0
  fi

  if [[ "$ok" -eq 1 ]]; then
    echo "ok   $url — cross-origin isolated"
    return 0
  fi

  # A response served by GitHub Pages explains the whole failure, so say so
  # rather than leaving someone to re-read a `_headers` file that is correct.
  if printf '%s\n' "$headers" | grep -qi '^x-github-request-id:'; then
    echo "     ...served by GitHub Pages, which cannot set these headers at all." >&2
    echo "     The site must be served by Cloudflare Pages (.github/workflows/pages.yml)." >&2
  fi
  return 1
}

main() {
  local base_url
  if [[ $# -ge 1 ]]; then
    base_url="${1%/}"
    shift
  else
    base_url="$(site_url_from_config)"
    base_url="${base_url%/}"
  fi

  local paths=("$@")
  if [[ ${#paths[@]} -eq 0 ]]; then
    paths=("/" "/demo/weblinux/")
  fi

  local failures=0 path
  for path in "${paths[@]}"; do
    check_url "${base_url}${path}" || failures=$((failures + 1))
  done

  if [[ "$failures" -gt 0 ]]; then
    echo >&2
    echo "$failures document(s) are not cross-origin isolated; the WebLinux demo will" >&2
    echo "fail with 'SharedArrayBuffer is not defined'." >&2
    return 1
  fi

  echo "all checked documents are cross-origin isolated"
}

main "$@"
