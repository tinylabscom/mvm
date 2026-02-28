# OpenClaw — mvm microVM Template

A multi-tenant microVM template for the OpenClaw platform. Builds NixOS-based
Firecracker guests that receive per-tenant configuration at runtime via mvm's
config and secrets drives.

## Architecture

```
┌─────────────────────────────────────────────────┐
│  Firecracker microVM (same image per role)      │
│                                                 │
│  /mnt/config/   ← mvm config drive (read-only) │
│    config.json       instance metadata          │
│    openclaw.json     app config (gateway/worker)│
│    openclaw.env      environment overrides      │
│                                                 │
│  /mnt/secrets/  ← mvm secrets drive (read-only) │
│    secrets.json      tenant secrets             │
│    openclaw-secrets.env  API keys               │
│                                                 │
│  /mnt/data/     ← mvm data drive (read-write)  │
│    (persistent storage, optional)               │
│                                                 │
│  systemd → openclaw-gateway (or worker)         │
│    reads config from /mnt/config                │
│    reads secrets from /mnt/secrets              │
└─────────────────────────────────────────────────┘
```

Drives are mounted by device path (`/dev/vdb`, `/dev/vdc`, `/dev/vdd`),
not by filesystem label, because the minimal initrd
(`includeDefaultModules = false`) doesn't include the udev rules that
create `/dev/disk/by-label/` symlinks. Firecracker drive ordering is
deterministic, so device paths are stable.

## Variants

| Name               | Role    | vCPUs | Memory | Data Disk |
| ------------------ | ------- | ----- | ------ | --------- |
| `openclaw-gateway` | gateway | 2     | 1 GiB  | none      |
| `openclaw-worker`  | worker  | 2     | 2 GiB  | 2 GiB     |

## Build

Build with mvmctl (from repo root):

```bash
mvmctl template build openclaw
```

Or directly with Nix:

```bash
cd nix/openclaw
nix build .#tenant-gateway
nix build .#tenant-worker
```

Each output contains `vmlinux` (kernel) and `rootfs.ext4` (root filesystem)
ready for Firecracker.

## Dev Usage

Run an openclaw gateway locally with `mvmctl`:

```bash
# 1. Build the template (runs nix build inside the Lima VM)
mvmctl template build openclaw

# 2. Run a gateway instance
mvmctl run --template openclaw --name my-gateway

# 3. Check status (shows IP address)
mvmctl vm status my-gateway

# 4. Forward the gateway port to localhost
mvmctl forward my-gateway 3000
# → localhost:3000 now proxies to the gateway inside the microVM
# Press Ctrl-C to stop forwarding

# 5. View serial console logs
mvmctl logs my-gateway

# 6. Stop the instance
mvmctl stop my-gateway
```

### Injecting configuration

Use `--config-dir` and `--secrets-dir` to inject files into the VM's
config and secrets drives. Every file in the directory is copied onto
the corresponding drive image before the VM boots.

```bash
# Prepare config and secrets directories
mkdir -p my-config my-secrets

# Gateway config (JSON)
cat > my-config/openclaw.json << 'EOF'
{
  "gateway": { "mode": "local", "port": 3000 },
  "models": ["claude-sonnet-4-5-20250929"],
  "version": "1"
}
EOF

# Environment overrides
echo 'OPENCLAW_LOG_LEVEL=debug' > my-config/openclaw.env

# API keys (secrets drive is also read-only inside the VM)
echo 'ANTHROPIC_API_KEY=sk-ant-...' > my-secrets/openclaw-secrets.env

# Run with injected config
mvmctl run --template openclaw --name my-gateway \
  --config-dir ./my-config \
  --secrets-dir ./my-secrets
```

Inside the VM, these files appear at:
- `/mnt/config/openclaw.json` — copied to `/var/lib/openclaw/config/openclaw.json` by `openclaw-init`
- `/mnt/config/openclaw.env` — loaded as `EnvironmentFile` by systemd
- `/mnt/secrets/openclaw-secrets.env` — loaded as `EnvironmentFile` by systemd

If no `openclaw.json` is provided, a minimal default is generated
(`gateway.mode=local`, `port=3000`), so the gateway starts without
requiring `openclaw setup`.

### Running the worker variant

```bash
mvmctl run --template openclaw --name my-worker --profile worker \
  --config-dir ./my-config \
  --secrets-dir ./my-secrets

# Workers use the data drive for persistent state (skills, sessions)
mvmctl forward my-worker 3000
```

## Fleet Usage

Fleet orchestration commands (tenants, pools, scaling) live in [mvmd](https://github.com/auser/mvmd):

```bash
# Create tenant with network isolation
mvmd tenant create acme --net-id 3 --subnet 10.240.3.0/24

# Create pools from template
mvmd pool create acme/gateways --template openclaw --role gateway
mvmd pool create acme/workers --template openclaw --role worker

# Build (one image per role, shared across all tenants)
mvmd pool build acme/gateways
mvmd pool build acme/workers

# Scale — each instance gets its own config/secrets drives
mvmd pool scale acme/workers --running 5
```

## File Structure

```
nix/openclaw/
├── flake.nix              Nix flake: builds vmlinux + rootfs.ext4 per role
├── mvm-profiles.toml      Profile/role → NixOS module mapping (consumed by mvm)
├── template.toml          mvm template metadata (variants, resources)
├── pkgs/
│   └── openclaw.nix       OpenClaw Node.js gateway package derivation
└── roles/
    ├── common.nix         Shared config (user, tmpfs, init service) — parameterized
    ├── gateway.nix        Gateway systemd service (reads /mnt/config, /mnt/secrets)
    └── worker.nix         Worker systemd service (reads /mnt/config, /mnt/secrets)
```
