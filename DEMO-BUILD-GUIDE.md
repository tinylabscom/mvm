# Demo Build Guide

This guide explains how to build and deploy the mvm demo site with WebLinux support.

## Overview

The mvm demo site has two components:

1. **Browser-tier WASM demo** (`web/mvm-demo/`) - Pure WebAssembly demo that runs on macOS
2. **WebLinux demo** (`web/weblinux-demo/`) - Full Linux VM in browser via QEMU-Wasm

The browser-tier WASM demo can be built on macOS, but the WebLinux demo requires the `qemu-wasm-smoke-pack` which can **only be built on Linux**.

## Building the Demo (macOS)

### Step 1: Build the browser-tier WASM demo

```bash
just demo-build
```

This produces assets at `public/public/demo/` (which gets copied to `public/dist/demo/` during the Astro build).

### Step 2: Build/Download the WebLinux pack

The WebLinux demo requires `qemu-wasm-smoke-pack` which contains:
- `qemu-system-x86_64.{js,wasm,worker.js}` - QEMU runtime
- `pack/` - firmware, kernel, rootfs
- Preloaded assets (`pack.data`, `pack.js`)
- `index.html`, `xterm-pty.js`

#### Option A: Build in the Linux builder VM (recommended)

```bash
just qemu-wasm-pack
```

This will:
1. Boot the Linux builder VM (if not running)
2. Copy the nix flake to the VM
3. Run `nix build .#qemu-wasm-smoke-pack` (10-30 minutes)
4. Copy the pack back to `./qemu-wasm-smoke-pack`

#### Option B: Download from GitHub releases

```bash
just qemu-wasm-pack-download [tag]
```

**Note:** The pack is NOT currently published to GitHub releases. This command is a template for when it becomes available.

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

Run `just qemu-wasm-pack` first to build the pack.

### Error: "Builder VM not found"

Boot the builder VM:
```bash
limactl start mvm-arm64
```

### Error: "qemu-wasm-smoke-pack.tar.gz not found in release"

The pack isn't published to GitHub releases yet. Use `just qemu-wasm-pack` to build it.

## File Locations

| Path | Purpose |
|------|---------|
| `web/mvm-demo/` | Browser-tier WASM demo source |
| `web/weblinux-demo/` | WebLinux demo source |
| `public/public/demo/` | Staging directory (before Astro build) |
| `public/dist/demo/` | Output directory (after Astro build) |
| `qemu-wasm-smoke-pack/` | Built WebLinux pack (created by `just qemu-wasm-pack`) |

## CI/CD

The CI/CD pipeline (`.github/workflows/pages.yml`) builds the pack inside the builder VM and stages it before deploying to Cloudflare Pages.
