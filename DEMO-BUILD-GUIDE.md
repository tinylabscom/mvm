# Demo Build Guide

This guide explains how to build and deploy the mvm demo site with WebLinux support.

## Prerequisites

### lima (required for Linux builder VM on macOS)

The Linux builder VM uses [lima](https://github.com/lima-vm/lima) (a Linux VM manager for macOS). If you don't have it installed:

```bash
# macOS
brew install lima

# Linux
# See https://github.com/lima-vm/lima#installation
```

**Windows:** Lima does not officially support Windows. For Windows development, use:

- WSL2 with Linux builder VM (via lima inside WSL2)
- Or use the [mvm-builderd](https://github.com/tinylabscom/mvm/blob/main/public/src/content/docs/guides/builder-vm.md) service

The builder VM (`mvm-arm64`) is shared across all worktrees and is required for:

- Running `mvmctl` commands that boot microVMs
- Nix builds and evaluations

### Other prerequisites

- [gh](https://cli.github.com/) - GitHub CLI (for `just qemu-wasm-pack-download`)
- [pnpm](https://pnpm.io/) - Node.js package manager
- [wasm-pack](https://rustwasm.github.io/wasm-pack/) - WebAssembly packager

## Overview

The mvm demo site has two components:

1. **Browser-tier WASM demo** (`web/mvm-demo/`) - Pure WebAssembly demo that runs on macOS
2. **WebLinux demo** (`web/weblinux-demo/`) - Full Linux VM in browser via QEMU-Wasm

The browser-tier WASM demo can be built on macOS. The WebLinux demo needs the `qemu-wasm-smoke-pack`, which is built and published by [mvm-images](https://github.com/tinylabscom/mvm-images) as a member of the image set `crates/mvm-core/images.lock` pins; this repository only downloads it.

## Building the Demo (macOS)

### Step 1: Build the browser-tier WASM demo

```bash
just demo-build
```

This produces assets at `public/public/demo/` (which gets copied to `public/dist/demo/` during the Astro build).

### Step 2: Download the WebLinux pack

The WebLinux demo requires `qemu-wasm-smoke-pack` which contains:

- `qemu-system-x86_64.{js,wasm,worker.js}` - QEMU runtime
- `pack/` - firmware, kernel, rootfs
- Preloaded assets (`pack.data`, `pack.js`)
- `index.html`, `xterm-pty.js`

```bash
just qemu-wasm-pack-download
```

This downloads the pack from the pinned image-set release, verifies the root's
digest and signature and the pack's digest against it, and unpacks it to
`./qemu-wasm-smoke-pack`.

### Step 3: Stage and build the full demo

```bash
just demo-build-all ./qemu-wasm-smoke-pack
```

This will:

1. Run `just demo-build` (browser-tier WASM)
2. Run `./web/weblinux-demo/build.sh ./qemu-wasm-smoke-pack` (WebLinux)

### Step 4: Build the Astro site

```bash
cd public && pnpm build
```

This produces `public/dist/` with all demo assets.

### Step 5: Deploy

```bash
npx wrangler pages deploy public/dist --project-name=mvm --branch=main
```

## Quick Start (After First Setup)

Once you've built the pack once, you can reuse it:

```bash
# Rebuild just the browser demo (fast)
just demo-build

# Stage both demos with existing pack
just demo-build-all ./qemu-wasm-smoke-pack

# Build Astro site
cd public && pnpm build

# Deploy
npx wrangler pages deploy public/dist --project-name=mvm --branch=main
```

## Troubleshooting

### Error: "qemu-wasm-smoke-pack not found"

Run `just qemu-wasm-pack-download` first to fetch the pack.

### Error: "Builder VM not found"

Boot the builder VM:

```bash
limactl start mvm-arm64
```

### Error: "qemu-wasm-smoke-pack.tar.gz not found in release"

The image-set release `images.lock` pins does not carry the pack. The pack is
built in mvm-images; advance the pin to a set that publishes it.

## File Locations

| Path                    | Purpose                                                |
| ----------------------- | ------------------------------------------------------ |
| `web/mvm-demo/`         | Browser-tier WASM demo source                          |
| `web/weblinux-demo/`    | WebLinux demo source                                   |
| `public/public/demo/`   | Staging directory (before Astro build)                 |
| `public/dist/demo/`     | Output directory (after Astro build)                   |
| `qemu-wasm-smoke-pack/` | Downloaded WebLinux pack (created by `just qemu-wasm-pack-download`) |

## CI/CD

The CI/CD pipeline (`.github/workflows/pages.yml`) builds the pack inside the builder VM and stages it before deploying to Cloudflare Pages.
