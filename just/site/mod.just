# ── Documentation ────────────────────────────────────────────────────────

# Install docs site dependencies
install:
    cd public && pnpm install

# Start docs dev server (stages the /demo wasm assets first if missing)
dev: demo-assets
    cd public && pnpm dev

# Build docs site (stages the /demo wasm assets first if missing)
build: demo-assets
    cd public && pnpm build

# Publish the docs site to Cloudflare Workers (dispatches workers.yml on main)
publish:
    # `workers.yml` runs automatically when website source lands on main, a
    # release is published, or a `v*` tag is pushed. This recipe remains the
    # operator-triggered publish/retry path.
    #
    # `--ref main`, never the current branch: production serves what is on main, and
    # dispatching from a branch would publish something nobody has merged.
    gh workflow run workers.yml --ref main
    @echo "Dispatched workers.yml on main. Watch it with: gh run watch \$(gh run list --workflow=workers.yml --limit 1 --json databaseId --jq '.[0].databaseId')"

# Check the live site sends the cross-origin isolation headers the demo needs
check-live-headers url="":
    # No argument checks the domain in public/astro.config.mjs; pass a URL to
    # check a preview deployment instead. `pnpm check:headers` gates the
    # `_headers` config — this one gates what the host actually sends, which is
    # a different question and the one that has been answered wrong.
    ./scripts/check-site-isolation-headers.sh {{ url }}

# Build the browser-tier microVM demo assets (wasm core + guest + fixtures)
demo:
    ./web/mvm-demo/build.sh

# Build the weblinux demo assets (requires Linux builder)
weblinux:
    ./web/weblinux-demo/build.sh

# Stage the browser WASM demo unless every generated asset class is present.
# WebLinux is staged separately from its verified release pack by workers.yml.
demo-assets:
    test -s public/public/demo/demo.js \
      && test -s public/public/demo/worker.js \
      && test -s public/public/demo/pkg/mvm_demo_web.js \
      && test -s public/public/demo/pkg/mvm_demo_web_bg.wasm \
      && test -s public/public/demo/guest/mvm-demo-guest.wasm \
      && test -s public/public/demo/fixtures/allowed.opt.wasm \
      && test -s public/public/demo/fixtures/denied.opt.wasm \
      && test -s public/public/demo/fixtures/unbound.opt.wasm \
      || just site::demo

# Download the qemu-wasm-smoke-pack from GitHub releases.
# This is faster than building from scratch (seconds vs 10-30 minutes).
# Usage: just site::qemu-pack [output-dir] [tag]
#   output-dir: Where to place the unpacked pack (default: ./qemu-wasm-smoke-pack)

# tag:        The boot-image tag to download from (default: latest)
qemu-pack *ARGS:
    ./scripts/download-qemu-wasm-smoke-pack.sh {{ ARGS }}

# Build all demo assets (wasm + weblinux); requires Linux for weblinux
# Usage: just site::demo-all [qemu-wasm-pack-path]
#   qemu-wasm-pack-path: Path to the built pack (default: ./qemu-wasm-smoke-pack)

# If not provided, downloads it first via just site::qemu-pack
demo-all *PACK_DIR:
    #!/usr/bin/env bash
    set -euo pipefail
    just site::demo
    # Determine pack directory
    if [ -n "{{ PACK_DIR }}" ]; then
      PACK_DIR="{{ PACK_DIR }}"
    else
      PACK_DIR="$PWD/qemu-wasm-smoke-pack"
    fi
    if [ ! -d "$PACK_DIR" ]; then
      echo "qemu-wasm-smoke-pack not found at $PACK_DIR"
      echo "Download it first with: just site::qemu-pack"
      exit 1
    fi
    ./web/weblinux-demo/build.sh "$PACK_DIR"
