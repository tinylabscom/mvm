# OpenClaw MicroVM Example

Run [OpenClaw](https://openclaw.com) in a Firecracker microVM, pre-built at Nix build time.

## How It Works

OpenClaw is pre-installed into the rootfs image at Nix build time using a three-phase process:

1. **FOD download** — `npm install openclaw@2026.3.2` in a fixed-output derivation (content-addressed by hash)
2. **autoPatchelf** — patches native `.node` addons to find nix store glibc/libstdc++
3. **esbuild bundle** — bundles 932 JS files into a single ~21MB file for fast startup on virtio-blk

The gateway starts in ~5 minutes on emulated ARM (QEMU), near-instant on subsequent starts within the same boot (V8 compile cache).

## Quick Start

```bash
# Build the template (first time takes a few minutes)
mvmctl template build openclaw

# Run with defaults (no API keys, localhost-only)
mvmctl run --template openclaw --name oc

# Run with config and API keys from host directories
mvmctl run --template openclaw --name oc \
    --volume ./config:/mnt/config \
    --volume ./secrets:/mnt/secrets

# Forward the gateway port to the host
mvmctl forward oc 3000:3000

# Check status and logs
mvmctl status
mvmctl logs oc
```

Or use the convenience script:

```bash
./start.sh [vm-name] [port]
```

## Configuration

### Default Config

Without any mounts, the VM generates a default config at `/var/lib/openclaw/config.json`:

```json
{
  "gateway": {
    "mode": "local",
    "port": 3000,
    "bind": "lan",
    "channelHealthCheckMinutes": 0,
    "auth": { "mode": "token" },
    "reload": { "mode": "off" },
    "controlUi": {
      "dangerouslyAllowHostHeaderOriginFallback": true
    }
  }
}
```

The default gateway token is `mvm` (set via `OPENCLAW_GATEWAY_TOKEN`).

### Overriding via Host Directories

Use `-v` to mount host directories into the VM:

```bash
mvmctl run --template openclaw --name oc \
    --volume ./config:/mnt/config \
    --volume ./secrets:/mnt/secrets
```

| Volume flag | Guest mount | Permissions | Purpose |
|---|---|---|---|
| `-v ./config:/mnt/config` | `/mnt/config` | Read-only (0444) | Config files |
| `-v ./secrets:/mnt/secrets` | `/mnt/secrets` | Read-only (0400) | API keys, tokens |

#### Config Drive (`/mnt/config`)

If `/mnt/config/openclaw.json` exists, it replaces the default config entirely. Environment variables are expanded via `envsubst`:

```json
{
  "gateway": {
    "mode": "local",
    "port": 3000,
    "bind": "lan",
    "auth": { "mode": "token" },
    "controlUi": {
      "dangerouslyAllowHostHeaderOriginFallback": true
    }
  }
}
```

If `/mnt/config/env.sh` exists, it's sourced before starting the gateway:

```bash
export OPENCLAW_INSTANCE_NAME=my-instance
export NODE_OPTIONS="--max-old-space-size=2048"
```

#### Secrets Drive (`/mnt/secrets`)

If `/mnt/secrets/api-keys.env` exists, it's sourced at startup. Put API keys here:

```bash
ANTHROPIC_API_KEY=sk-ant-...
OPENCLAW_GATEWAY_TOKEN=my-custom-token
```

The `OPENCLAW_GATEWAY_TOKEN` defaults to `mvm` if not set via secrets or config env.

### Drive Model

The microVM has four block devices:

| Device | Mount | Type | Description |
|---|---|---|---|
| `/dev/vda` | `/` | ext4 (rw) | Root filesystem (Nix-built image) |
| `/dev/vdb` | `/mnt/config` | ext4 (ro) | Config drive from `-v dir:/mnt/config` |
| `/dev/vdc` | `/mnt/secrets` | ext4 (ro) | Secrets drive from `-v dir:/mnt/secrets` |
| `/dev/vdd` | `/mnt/data` | ext4 (rw) | Data volume from `-v host:guest:size` |

All drives except root are optional — the init script mounts them best-effort.

## Architecture

```
Host (macOS/Linux)
  └─ Lima VM (Ubuntu)
      └─ Firecracker microVM
          ├─ Node.js 22 (Nix-built)
          ├─ OpenClaw bundle (esbuild, pre-built)
          ├─ Control UI (pre-built static assets)
          ├─ /mnt/config → -v dir:/mnt/config (read-only)
          ├─ /mnt/secrets → -v dir:/mnt/secrets (read-only)
          └─ /var/lib/openclaw (tmpfs workspace)
```

## Files

- `flake.nix` — Nix build: FOD download, autoPatchelf, esbuild bundle, mkGuest image
- `start.sh` — Convenience script to build template and run
- `config/openclaw.json` — Sample OpenClaw config (mounted to `/mnt/config`)
- `secrets/api-keys.env` — API key template (mounted to `/mnt/secrets`)

## Updating OpenClaw

To update the OpenClaw version:

1. Edit `version` in `openclaw-src` derivation in `flake.nix`
2. Set `outputHash = "";` (empty string)
3. Build — Nix will fail and print the correct hash
4. Set `outputHash` to the printed hash
5. Rebuild
