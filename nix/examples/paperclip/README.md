# Paperclip MicroVM Example

Run [Paperclip](https://github.com/paperclipai/paperclip) — an open-source AI agent orchestration platform — inside a Firecracker microVM.

Paperclip coordinates multiple AI agents (Claude Code, Codex, OpenClaw, Cursor) as employees in a virtual company, with org charts, heartbeat-based execution, cost control, and ticket-based task management.

## How It Works

The Nix flake builds Paperclip in three phases:

1. **FOD (fixed-output derivation)** — clones the repo at a pinned commit and runs `pnpm install --frozen-lockfile`. Network access is allowed; output is verified by content hash.
2. **autoPatchelf** — patches native binaries (embedded PostgreSQL, etc.) to find glibc/libstdc++ in the Nix store.
3. **TypeScript build** — compiles the server and UI with `pnpm build`.

The result is packaged into a microVM rootfs with busybox init, the mvm guest agent, and Node.js 22.

## Quick Start

```bash
# Build the template
mvmctl template build paperclip

# Run with default settings (embedded PostgreSQL, no auth)
mvmctl run --template paperclip --name paperclip -p 3100:3100

# Forward the port and open the UI
mvmctl forward paperclip
open http://localhost:3100

# Or use the convenience script
./nix/examples/paperclip/start.sh
```

## Configuration

### Default Config

With no volume mounts, Paperclip starts with embedded PostgreSQL and `local_trusted` mode (no authentication required). Data is stored on a tmpfs at `/var/lib/paperclip/`.

### Overriding via Host Directories

```bash
mvmctl run --template paperclip --name paperclip \
  -v ./nix/examples/paperclip/config:/mnt/config \
  -v ./nix/examples/paperclip/secrets:/mnt/secrets \
  -p 3100:3100
```

### Config Drive (`/mnt/config`)

| File | Purpose |
|------|---------|
| `env.sh` | Environment variables sourced at startup (PORT, deployment mode, etc.) |

### Secrets Drive (`/mnt/secrets`)

| File | Purpose |
|------|---------|
| `api-keys.env` | API keys for agent adapters (ANTHROPIC_API_KEY, OPENAI_API_KEY) |

Secrets are mounted read-only and copied to a tmpfs at `/run/mvm-secrets/` with restricted permissions.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3100` | Server port |
| `PAPERCLIP_DEPLOYMENT_MODE` | `local_trusted` | `local_trusted` or `authenticated` |
| `PAPERCLIP_DEPLOYMENT_EXPOSURE` | `private` | `private` or `public` |
| `PAPERCLIP_INSTANCE_ID` | `default` | Instance identifier |
| `ANTHROPIC_API_KEY` | — | For Claude agent adapter |
| `OPENAI_API_KEY` | — | For Codex agent adapter |

## Architecture

```
macOS / Linux Host
  └── Lima VM (Ubuntu, /dev/kvm)
        └── Firecracker microVM (172.16.0.2)
              ├── busybox init (PID 1)
              ├── mvm-guest-agent (vsock)
              └── paperclip server (Node.js, port 3100)
                    ├── Express 5 API
                    ├── React 19 UI (SERVE_UI=true)
                    └── Embedded PostgreSQL (PGlite)
```

## Files

| File | Purpose |
|------|---------|
| `flake.nix` | Nix build pipeline: FOD + autoPatchelf + build + mkGuest |
| `config/env.sh` | Optional environment variables (sourced at runtime) |
| `secrets/api-keys.env` | API keys template (sourced at runtime) |
| `start.sh` | Convenience script: build template + run VM |
| `README.md` | This file |

## Updating Paperclip

1. Find the latest commit: `gh api repos/paperclipai/paperclip/commits --jq '.[0].sha'`
2. Update `rev` and `version` in `flake.nix`
3. Set `outputHash = ""` in the `paperclip-src` derivation
4. Build to get the new hash: `mvmctl template build paperclip`
5. Copy the correct hash from the error message into `outputHash`
6. Rebuild: `mvmctl template build paperclip --force`
